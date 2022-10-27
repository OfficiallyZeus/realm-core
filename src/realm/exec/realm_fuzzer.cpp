/*
 * realm_fuzzer.cpp
 *
 *  Created on: Oct 4, 2022
 *      Author: jed
 */

#include "realm/object-store/shared_realm.hpp"
#include "realm/object-store/object.hpp"
#include "realm/object-store/results.hpp"
#include <realm/object-store/util/scheduler.hpp>
#include <realm/unicode.hpp>
#include <external/json/json.hpp>

#include <cstdlib>
#include <iostream>
#include <string>
#include <map>
#include <uv.h>

using namespace realm;

std::map<TableKey, std::vector<std::string>> deleted_objects;

static Mixed mutate(Mixed val, ColKey col_key, std::string& buffer)
{
    switch (col_key.get_type()) {
        case col_type_Int:
            return val.get_int() + 5;
        case col_type_String: {
            buffer = "MUTATED";
            StringData str = val.get_string();
            if (str.size() > 0) {
                bool is_upper = str[0] < 'a';
                if (auto res = case_map(str, !is_upper)) {
                    buffer = *res;
                }
            }
            return buffer;
        }
        case col_type_Bool:
            return !val.get_bool();
        case col_type_Float:
            return 25;
        case col_type_Double:
            return 25;
        case col_type_Timestamp:
            return 25;
        case col_type_Decimal:
            return 25;
        default:
            break;
    }
    return {};
}

class Fuzzer {
public:
    Fuzzer(SharedRealm r, std::string inp)
        : m_realm(r)
        , m_fuzzy(inp)
    {
        const Schema& schema = m_realm->schema();
        for (auto& os : schema) {
            auto& t = m_table_info.emplace_back();
            t.key = os.table_key;
            t.name = os.name;
            std::vector<PropInfo>& props = m_table_info.back().properties;
            for (auto prop : os.persisted_properties) {
                if (!prop.is_primary) {
                    auto& p = props.emplace_back();
                    p.key = prop.column_key;
                    p.name = prop.name;
                    break;
                }
            }
        }
    }
    bool step()
    {
        auto step = get_instr(7);
        switch (step) {
            case 0:
                break;
            case 1: {
                if (m_object_info.size() < 20) {
                    auto table_index = get_instr(m_table_info.size());
                    auto table_ref = m_realm->read_group().get_table(m_table_info[table_index].key);
                    if (auto sz = table_ref->size()) {
                        auto object_index = get_instr(sz);
                        m_object_info.emplace_back(m_table_info[table_index]);
                        ObjInfo& i = m_object_info.back();
                        i.object = Object(m_realm, i.table->name, object_index);
                        i.m_token = i.object.add_notification_callback([](CollectionChangeSet) {
                            // std::cout << "Notification received" << std::endl;
                        });
                        // std::cout << "Object added" << std::endl;
                    }
                }
                break;
            }
            case 2: {
                m_realm->async_begin_transaction([this]() {
                    if (!m_object_info.empty()) {
                        ObjInfo& i = m_object_info[get_instr(m_object_info.size())];
                        auto& prop = i.table->properties[get_instr(i.table->properties.size())];
                        auto obj = i.object.obj();
                        auto mixed = obj.get_any(prop.key);
                        std::string buffer;
                        mixed = mutate(mixed, prop.key, buffer);
                        obj.set_any(prop.key, mixed);
                        m_realm->async_commit_transaction([](auto) {
                            // std::cout << "Object mutated" << std::endl;
                        });
                    }
                });
                break;
            }
            case 3: {
                if (!m_object_info.empty()) {
                    auto it = m_object_info.begin() + (get_instr(m_object_info.size()));
                    m_object_info.erase(it);
                    // std::cout << "Object removed" << std::endl;
                }
                break;
            }
            case 4: {
                // std::cout << "Null transaction" << std::endl;
                m_realm->begin_transaction();
                m_realm->commit_transaction();
                break;
            }
            case 5: {
                if (!m_frozen_realm) {
                    // std::cout << "Freeze" << std::endl;
                    m_realm->read_group();
                    m_frozen_realm = m_realm->freeze();
                }
                break;
            }
            case 6: {
                if (m_frozen_realm) {
                    // std::cout << "Delete frozen" << std::endl;
                    m_frozen_realm = nullptr;
                }
                break;
            }
            case 7: {
                break;
            }
            case 8: {
                auto table_index = get_instr(m_table_info.size());
                auto table_ref = m_realm->read_group().get_table(m_table_info[table_index].key);
                m_realm->begin_transaction();
                auto sz = table_ref->size();
                if (sz > 10) {
                    auto object_index = get_instr(sz);
                    auto obj = table_ref->get_object(object_index);
                    std::vector<std::string>& objects = deleted_objects[table_ref->get_key()];
                    objects.push_back(obj.to_string());
                    obj.remove();
                    m_realm->commit_transaction();
                }
                else {
                    m_realm->cancel_transaction();
                }
                break;
            }
            case 9: {
                auto table_index = get_instr(m_table_info.size());
                auto table_ref = m_realm->read_group().get_table(m_table_info[table_index].key);
                std::vector<std::string>& objects = deleted_objects[table_ref->get_key()];
                if (!objects.empty()) {
                    m_realm->begin_transaction();
                    std::string values = objects.back();
                    auto j = nlohmann::json::parse(values);
                    objects.pop_back();
                    auto pk_col = table_ref->get_primary_key_column();
                    Obj obj;
                    if (pk_col) {
                        std::string col_name{table_ref->get_column_name(pk_col)};
                        auto id = j[col_name];
                        Mixed pk_val;
                        std::string string_val = id.get<std::string>();
                        if (pk_col.get_type() == col_type_String) {
                            pk_val = Mixed(StringData(string_val));
                        }
                        obj = table_ref->create_object_with_primary_key(pk_val);
                    }
                    else {
                        obj = table_ref->create_object();
                    }
                    for (auto col : table_ref->get_column_keys()) {
                        if (col == pk_col) {
                            continue;
                        }
                    }
                    m_realm->commit_transaction();
                }
                break;
            }
            default:
                break;
        }
        // std::cout << "Verify" << std::endl;
        util::StderrLogger logger;
        m_realm->read_group().verify_cluster(logger);
        return done;
    }

private:
    struct PropInfo {
        ColKey key;
        std::string name;
    };
    struct TableInfo {
        TableKey key;
        std::string name;
        std::vector<PropInfo> properties;
    };
    struct ObjInfo {
        ObjInfo(const TableInfo& t)
            : table(&t)
        {
        }
        const TableInfo* table;
        Object object;
        NotificationToken m_token;
    };
    SharedRealm m_realm;
    SharedRealm m_frozen_realm;
    std::vector<TableInfo> m_table_info;
    std::vector<ObjInfo> m_object_info;
    std::string m_fuzzy;
    size_t m_step = 0;
    bool done = false;

    int get_instr(size_t max)
    {
        if (m_step < m_fuzzy.length()) {
            return (int(uint8_t(m_fuzzy[m_step++])) + 1) % max;
        }
        done = true;
        return 0;
    }
};

extern "C" int LLVMFuzzerTestOneInput(const char* data, size_t size);

int LLVMFuzzerTestOneInput(const char* data, size_t size)
{
    RealmConfig config;
    config.path = "default.realm";

    // std::cout << "---------------------------" << std::endl;
    // std::cout << "Sequence length: " << size << std::endl;
    uv_loop_t* loop = uv_default_loop();
    uv_idle_t idle_handle;
    idle_handle.data = new Fuzzer(Realm::get_shared_realm(config), std::string(data, size));
    uv_idle_init(loop, &idle_handle);
    uv_idle_start(&idle_handle, [](uv_idle_t* handle) {
        Fuzzer* fuzzer = static_cast<Fuzzer*>(handle->data);
        auto done = fuzzer->step();
        if (done) {
            uv_idle_stop(handle);
            delete fuzzer;
        }
    });
    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}
