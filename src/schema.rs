//! Derive the output schema (column names and PostgreSQL types) that a
//! Substrait plan produces, so callers can be told the exact `AS` clause to
//! write. Every function returns `None` when the plan uses a construct we do
//! not yet model, letting the caller fall back gracefully rather than fail.

use substrait::proto::{Expression, Plan, Rel, RelCommon, Type};

/// The output schema derived from a Substrait plan: parallel column names and
/// PostgreSQL type names.
pub struct DerivedSchema {
    pub names: Vec<String>,
    pub types: Vec<String>,
}

impl DerivedSchema {
    /// Number of output columns.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the plan produces no columns.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Render the column list as it would appear inside `AS t(...)`, e.g.
    /// `"L_ORDERKEY bigint, REVENUE numeric"`.
    pub fn as_clause(&self) -> String {
        self.names
            .iter()
            .zip(self.types.iter())
            .map(|(name, pg_type)| format!("{name} {pg_type}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Derive the output schema from a plan's Root relation. Returns `None` when
/// there is no Root relation, when the plan uses an unsupported construct, or
/// when the declared column names do not line up with the derived types.
pub fn extract_schema(plan: &Plan) -> Option<DerivedSchema> {
    use substrait::proto::plan_rel::RelType;

    let (names, input) = plan.relations.first().and_then(|rel| {
        if let Some(RelType::Root(root)) = &rel.rel_type {
            Some((root.names.clone(), root.input.as_ref()))
        } else {
            None
        }
    })?;

    let types = derive_rel_output_types(input?)?;
    if names.len() != types.len() {
        return None;
    }

    Some(DerivedSchema { names, types })
}

/// Map a Substrait type to a PostgreSQL type name.
#[allow(deprecated)] // Kind::Timestamp is deprecated upstream but still emitted by plans.
fn substrait_type_to_pg_name(t: &Type) -> Option<String> {
    use substrait::proto::r#type::Kind;
    let name = match &t.kind {
        Some(Kind::Bool(_)) => "boolean",
        Some(Kind::I8(_)) | Some(Kind::I16(_)) => "smallint",
        Some(Kind::I32(_)) => "integer",
        Some(Kind::I64(_)) => "bigint",
        Some(Kind::Fp32(_)) => "real",
        Some(Kind::Fp64(_)) => "double precision",
        Some(Kind::Decimal(_)) => "numeric",
        Some(Kind::String(_)) | Some(Kind::FixedChar(_)) | Some(Kind::Varchar(_)) => "text",
        Some(Kind::Date(_)) => "date",
        Some(Kind::Timestamp(_)) | Some(Kind::PrecisionTimestamp(_)) => "timestamp",
        Some(Kind::IntervalYear(_)) | Some(Kind::IntervalDay(_)) => "interval",
        _ => return None,
    };
    Some(name.to_string())
}

/// Apply an emit remapping (if any) to a relation's direct output.
fn apply_emit(common: Option<&RelCommon>, types: Vec<String>) -> Option<Vec<String>> {
    use substrait::proto::rel_common::EmitKind;
    if let Some(common) = common {
        if let Some(EmitKind::Emit(emit)) = &common.emit_kind {
            return emit
                .output_mapping
                .iter()
                .map(|&i| types.get(i as usize).cloned())
                .collect();
        }
    }
    Some(types)
}

/// Derive the output column types of a relation's single input, or an empty
/// vec when there is no input.
fn input_types(input: Option<&Rel>) -> Option<Vec<String>> {
    match input {
        Some(rel) => derive_rel_output_types(rel),
        None => Some(Vec::new()),
    }
}

/// Compute the output column types of a Substrait relation tree from the types
/// the plan declares. Returns `None` on any construct we do not model.
fn derive_rel_output_types(rel: &Rel) -> Option<Vec<String>> {
    use substrait::proto::rel::RelType;

    match &rel.rel_type {
        Some(RelType::Read(read)) => {
            let types = match read.base_schema.as_ref().and_then(|s| s.r#struct.as_ref()) {
                Some(st) => st
                    .types
                    .iter()
                    .map(substrait_type_to_pg_name)
                    .collect::<Option<Vec<_>>>()?,
                None => Vec::new(),
            };
            apply_emit(read.common.as_ref(), types)
        }
        Some(RelType::Filter(filter)) => {
            let types = input_types(filter.input.as_deref())?;
            apply_emit(filter.common.as_ref(), types)
        }
        Some(RelType::Sort(sort)) => {
            let types = input_types(sort.input.as_deref())?;
            apply_emit(sort.common.as_ref(), types)
        }
        Some(RelType::Fetch(fetch)) => {
            let types = input_types(fetch.input.as_deref())?;
            apply_emit(fetch.common.as_ref(), types)
        }
        Some(RelType::Project(project)) => {
            let input_types = input_types(project.input.as_deref())?;
            let mut types = input_types.clone();
            for expr in &project.expressions {
                types.push(derive_expr_type(expr, &input_types)?);
            }
            apply_emit(project.common.as_ref(), types)
        }
        Some(RelType::Cross(cross)) => {
            let mut types = input_types(cross.left.as_deref())?;
            types.extend(input_types(cross.right.as_deref())?);
            apply_emit(cross.common.as_ref(), types)
        }
        Some(RelType::Join(join)) => {
            let mut types = input_types(join.left.as_deref())?;
            types.extend(input_types(join.right.as_deref())?);
            apply_emit(join.common.as_ref(), types)
        }
        Some(RelType::Aggregate(agg)) => {
            let input_types = input_types(agg.input.as_deref())?;
            let mut types = Vec::new();
            if let Some(grouping) = agg.groupings.first() {
                #[allow(deprecated)]
                for group_expr in &grouping.grouping_expressions {
                    types.push(derive_expr_type(group_expr, &input_types)?);
                }
            }
            for measure in &agg.measures {
                let t = measure
                    .measure
                    .as_ref()
                    .and_then(|m| m.output_type.as_ref())
                    .and_then(substrait_type_to_pg_name)?;
                types.push(t);
            }
            apply_emit(agg.common.as_ref(), types)
        }
        _ => None,
    }
}

/// Compute an expression's output type from the types the plan declares.
fn derive_expr_type(expr: &Expression, input_types: &[String]) -> Option<String> {
    use substrait::proto::expression::literal::LiteralType;
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Literal(lit)) => {
            let name = match &lit.literal_type {
                Some(LiteralType::Boolean(_)) => "boolean",
                Some(LiteralType::I8(_)) | Some(LiteralType::I16(_)) => "smallint",
                Some(LiteralType::I32(_)) => "integer",
                Some(LiteralType::I64(_)) => "bigint",
                Some(LiteralType::Fp32(_)) => "real",
                Some(LiteralType::Fp64(_)) => "double precision",
                Some(LiteralType::Decimal(_)) => "numeric",
                Some(LiteralType::String(_))
                | Some(LiteralType::FixedChar(_))
                | Some(LiteralType::VarChar(_)) => "text",
                Some(LiteralType::Date(_)) => "date",
                _ => return None,
            };
            Some(name.to_string())
        }
        Some(RexType::Selection(sel)) => {
            use substrait::proto::expression::field_reference::ReferenceType;
            use substrait::proto::expression::reference_segment::ReferenceType as SegRefType;
            if let Some(ReferenceType::DirectReference(direct)) = &sel.reference_type {
                if let Some(SegRefType::StructField(sf)) = &direct.reference_type {
                    return input_types.get(sf.field as usize).cloned();
                }
            }
            None
        }
        Some(RexType::ScalarFunction(func)) => func
            .output_type
            .as_ref()
            .and_then(substrait_type_to_pg_name),
        Some(RexType::Cast(cast)) => cast.r#type.as_ref().and_then(substrait_type_to_pg_name),
        Some(RexType::IfThen(if_then)) => {
            let branch = if_then
                .ifs
                .first()
                .and_then(|c| c.then.as_ref())
                .or(if_then.r#else.as_deref())?;
            derive_expr_type(branch, input_types)
        }
        Some(RexType::Subquery(subquery)) => {
            use substrait::proto::expression::subquery::SubqueryType;
            match &subquery.subquery_type {
                Some(SubqueryType::Scalar(scalar)) => {
                    let rel = scalar.input.as_ref()?;
                    derive_rel_output_types(rel)?.into_iter().next()
                }
                _ => Some("boolean".to_string()),
            }
        }
        _ => None,
    }
}
