/// Get a human-readable name for a Substrait relation type
pub fn get_relation_type_name(rel_type: &substrait::proto::rel::RelType) -> &'static str {
    use substrait::proto::rel::RelType;
    match rel_type {
        RelType::Project(_) => "Project",
        RelType::Read(_) => "Read",
        RelType::Aggregate(_) => "Aggregate",
        RelType::Sort(_) => "Sort",
        RelType::Filter(_) => "Filter",
        RelType::Join(_) => "Join",
        RelType::Cross(_) => "Cross",
        RelType::Fetch(_) => "Fetch",
        RelType::Window(_) => "Window",
        RelType::Exchange(_) => "Exchange",
        RelType::HashJoin(_) => "HashJoin",
        RelType::MergeJoin(_) => "MergeJoin",
        RelType::NestedLoopJoin(_) => "NestedLoopJoin",
        RelType::Set(_) => "Set",
        RelType::ExtensionSingle(_) => "ExtensionSingle",
        RelType::ExtensionMulti(_) => "ExtensionMulti",
        RelType::ExtensionLeaf(_) => "ExtensionLeaf",
        RelType::Ddl(_) => "DDL",
        RelType::Write(_) => "Write",
        RelType::Reference(_) => "Reference",
        RelType::Update(_) => "Update",
        RelType::Expand(_) => "Expand",
    }
}

/// Get a human-readable name for a Substrait expression type
pub fn get_expression_type_name(rex_type: &substrait::proto::expression::RexType) -> &'static str {
    use substrait::proto::expression::RexType;
    match rex_type {
        RexType::Literal(_) => "Literal",
        RexType::Selection(_) => "Selection",
        RexType::ScalarFunction(_) => "ScalarFunction",
        RexType::WindowFunction(_) => "WindowFunction",
        RexType::IfThen(_) => "IfThen",
        RexType::SwitchExpression(_) => "SwitchExpression",
        RexType::SingularOrList(_) => "SingularOrList",
        RexType::MultiOrList(_) => "MultiOrList",
        RexType::Cast(_) => "Cast",
        RexType::Subquery(_) => "Subquery",
        RexType::Nested(_) => "Nested",
        RexType::Enum(_) => "Enum",
        RexType::DynamicParameter(_) => "DynamicParameter",
    }
}
