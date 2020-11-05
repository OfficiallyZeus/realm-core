#include "catch2/catch.hpp"

#include "util/test_file.hpp"
#include "util/index_helpers.hpp"

#include "binding_context.hpp"
#include "set.hpp"
#include "object.hpp"
#include "object_schema.hpp"
#include "property.hpp"
#include "results.hpp"
#include "schema.hpp"

#include "impl/realm_coordinator.hpp"
// #include "impl/object_accessor_impl.hpp"

#include <realm/version.hpp>
#include <realm/db.hpp>

using namespace realm;

TEST_CASE("set")
{
    InMemoryTestFile config;
    config.automatic_change_notifications = false;
    auto r = Realm::get_shared_realm(config);
    r->update_schema({
        {"table", {{"int_set", PropertyType::Set | PropertyType::Int}}},
    });

    auto& coordinator = *_impl::RealmCoordinator::get_coordinator(config.path);

    auto table = r->read_group().get_table("class_table");
    ColKey col_int_set = table->get_column_key("int_set");

    r->begin_transaction();
    Obj obj = table->create_object();
    r->commit_transaction();

    SECTION("basics")
    {
        object_store::Set set{r, obj, col_int_set};
        auto write = [&](auto&& f) {
            r->begin_transaction();
            f();
            r->commit_transaction();
            advance_and_notify(*r);
        };
        static_cast<void>(write);
        static_cast<void>(coordinator);
    }
}