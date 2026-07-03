/**************************************************************************
   Copyright (c) 2017 sewenew

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 *************************************************************************/

#ifndef SEWENEW_REDISPLUSPLUS_TEST_JWT_AUTH_TEST_HPP
#define SEWENEW_REDISPLUSPLUS_TEST_JWT_AUTH_TEST_HPP

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <sw/redis++/connection.h>
#include <sw/redis++/connection_pool.h>
#include <sw/redis++/jwt_auth.h>
#include "utils.h"

namespace sw {

namespace redis {

namespace test {

namespace {

inline std::string random_segment(std::size_t len = 16) {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::uniform_int_distribution<std::size_t> dist(0, sizeof(kAlphabet) - 2);
    std::string out;
    out.reserve(len);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kAlphabet[dist(rng)]);
    }
    return out;
}

} // namespace

template <typename RedisInstance>
std::string JwtAuthTest<RedisInstance>::_fake_jwt() const {
    // Fake JWT shape with a random payload. No crypto and no network.
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + random_segment(24) + "." + random_segment(32);
}

template <typename RedisInstance>
ConnectionOptions JwtAuthTest<RedisInstance>::_unreachable_opts(
        const std::string &password) const {
    ConnectionOptions opts;
    opts.host = "127.0.0.1";
    opts.port = 1;
    opts.password = password;
    opts.connect_timeout = std::chrono::milliseconds(1);
    opts.socket_timeout = std::chrono::milliseconds(1);
    opts.user = _opts.user;
    return opts;
}

template <typename RedisInstance>
ConnectionPoolOptions JwtAuthTest<RedisInstance>::_pool_opts(std::size_t size) const {
    ConnectionPoolOptions opts;
    opts.size = size;
    opts.wait_timeout = std::chrono::milliseconds(50);
    return opts;
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_seed_idle_connections(ConnectionPool &pool,
        std::size_t n,
        const std::string &password,
        std::uint64_t generation) const {
    auto opts = pool.connection_options();
    opts.password = password;
    for (std::size_t i = 0; i < n; ++i) {
        auto conn = Connection::make_unconnected(opts);
        conn.set_password(password);
        conn.set_password_generation(generation);
        pool.release(std::move(conn));
    }
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::run() {
    _test_jwt_as_password();
    _test_credentials();
    _test_credentials_thread_safety();
    _test_manager_validation();
    _test_manager_refresh();
    _test_register_pool();
    _test_pool_password_update();
    _test_connection_helpers();
    _test_gradual_reauth();
    _test_manager_applies_to_pools();
    _test_background_refresh();
    _test_configurable_options();
    _test_concurrent_refresh();
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_jwt_as_password() {
    auto jwt = _fake_jwt();
    ConnectionOptions opts = _opts;
    opts.password = jwt;
    REDIS_ASSERT(opts.password == jwt, "failed to set JWT as connection password");
    REDIS_ASSERT(opts.password.find('.') != std::string::npos,
            "JWT password should keep dotted segments");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_credentials() {
    JwtCredentials empty;
    REDIS_ASSERT(empty.password().empty(), "default credentials should have empty password");
    REDIS_ASSERT(empty.generation() == 0, "default credentials generation should be 0");

    auto jwt = _fake_jwt();
    JwtCredentials creds(jwt);
    REDIS_ASSERT(creds.password() == jwt, "credentials should store initial password");
    REDIS_ASSERT(creds.generation() == 1, "initial non-empty password should use generation 1");

    auto snap = creds.snapshot();
    REDIS_ASSERT(snap.first == jwt && snap.second == 1,
            "credentials snapshot should match password and generation");

    auto g1 = creds.generation();
    auto t2 = _fake_jwt();
    auto g2 = creds.update(t2);
    REDIS_ASSERT(g2 == g1 + 1, "update should bump generation");
    REDIS_ASSERT(creds.password() == t2, "update should replace password");

    auto t3 = _fake_jwt();
    auto g3 = creds.update(t3);
    REDIS_ASSERT(g3 == g2 + 1, "second update should bump generation again");
    REDIS_ASSERT(creds.password() != t2, "password should change on update");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_credentials_thread_safety() {
    auto creds = std::make_shared<JwtCredentials>(_fake_jwt());
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([creds, &start]() {
            while (!start.load()) {
            }
            for (int j = 0; j < 100; ++j) {
                creds->update("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + random_segment(24)
                        + "." + random_segment(32));
                auto snap = creds->snapshot();
                REDIS_ASSERT(!snap.first.empty(), "concurrent snapshot password should be set");
                REDIS_ASSERT(snap.second >= 1, "concurrent snapshot generation should be set");
            }
        });
    }
    start = true;
    for (auto &t : threads) {
        t.join();
    }
    REDIS_ASSERT(creds->generation() >= 1, "credentials should remain valid after races");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_manager_validation() {
    {
        bool thrown = false;
        try {
            JwtAuthOptions opts;
            JwtAuthManager manager(opts);
        } catch (const Error &) {
            thrown = true;
        }
        REDIS_ASSERT(thrown, "manager should require token_fetcher");
    }

    {
        bool thrown = false;
        try {
            JwtAuthOptions opts;
            opts.token_fetcher = [this]() { return _fake_jwt(); };
            opts.reauth_batch_size = 0;
            JwtAuthManager manager(opts);
        } catch (const Error &) {
            thrown = true;
        }
        REDIS_ASSERT(thrown, "manager should reject zero reauth_batch_size");
    }

    {
        bool thrown = false;
        try {
            JwtAuthOptions opts;
            opts.token_fetcher = [this]() { return _fake_jwt(); };
            JwtAuthManager manager(opts, nullptr);
        } catch (const Error &) {
            thrown = true;
        }
        REDIS_ASSERT(thrown, "manager should reject null credentials");
    }

    {
        bool thrown = false;
        try {
            JwtAuthOptions opts;
            opts.token_fetcher = []() { return std::string(); };
            JwtAuthManager manager(opts);
        } catch (const Error &) {
            thrown = true;
        }
        REDIS_ASSERT(thrown, "manager should reject empty initial token");
    }

    auto calls = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions opts;
    opts.token_fetcher = [calls, this]() {
        if (calls->fetch_add(1) == 0) {
            return _fake_jwt();
        }
        return std::string();
    };
    opts.refresh_interval = std::chrono::hours(1);
    JwtAuthManager manager(opts);
    bool thrown = false;
    try {
        manager.refresh_now();
    } catch (const Error &) {
        thrown = true;
    }
    REDIS_ASSERT(thrown, "refresh_now should reject empty token");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_manager_refresh() {
    auto counter = std::make_shared<std::atomic<int>>(0);
    auto seen = std::make_shared<std::vector<std::string>>();
    auto seen_mu = std::make_shared<std::mutex>();

    JwtAuthOptions opts;
    opts.token_fetcher = [counter, seen, seen_mu, this]() {
        counter->fetch_add(1);
        auto token = _fake_jwt();
        {
            std::lock_guard<std::mutex> lock(*seen_mu);
            seen->push_back(token);
        }
        return token;
    };
    opts.refresh_interval = std::chrono::hours(1);

    JwtAuthManager manager(opts);
    REDIS_ASSERT(counter->load() == 1, "constructor should fetch initial token");
    REDIS_ASSERT(manager.refresh_count() == 1, "initial refresh_count should be 1");
    REDIS_ASSERT(!manager.credentials()->password().empty(), "initial password should be set");
    REDIS_ASSERT(manager.credentials()->generation() == 1, "initial generation should be 1");

    auto first = manager.credentials()->password();
    auto g1 = manager.credentials()->generation();
    manager.refresh_now();
    auto second = manager.credentials()->password();
    auto g2 = manager.credentials()->generation();
    REDIS_ASSERT(first != second, "refresh_now should rotate JWT");
    REDIS_ASSERT(g2 == g1 + 1, "refresh_now should bump generation");
    REDIS_ASSERT(counter->load() == 2, "refresh_now should invoke token_fetcher");
    REDIS_ASSERT(manager.refresh_count() == 2, "refresh_count should track fetches");

    {
        std::lock_guard<std::mutex> lock(*seen_mu);
        REDIS_ASSERT(seen->size() == 2, "should record each fetched token");
        REDIS_ASSERT((*seen)[0] != (*seen)[1], "consecutive tokens should differ");
    }

    auto creds = std::make_shared<JwtCredentials>(_fake_jwt());
    auto g0 = creds->generation();
    JwtAuthOptions opts2;
    opts2.token_fetcher = [this]() { return _fake_jwt(); };
    opts2.refresh_interval = std::chrono::hours(1);
    JwtAuthManager manager2(opts2, creds);
    REDIS_ASSERT(manager2.credentials().get() == creds.get(),
            "manager should reuse provided credentials");
    REDIS_ASSERT(manager2.refresh_count() == 0,
            "shared-credentials ctor should not count an initial fetch");
    manager2.refresh_now();
    REDIS_ASSERT(creds->generation() == g0 + 1,
            "refresh_now should update shared credentials");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_register_pool() {
    JwtAuthOptions opts;
    opts.token_fetcher = [this]() { return _fake_jwt(); };
    opts.refresh_interval = std::chrono::hours(1);
    opts.reauth_batch_interval = std::chrono::milliseconds(0);
    opts.prefer_inline_reauth = false;
    JwtAuthManager manager(opts);

    auto jwt = manager.credentials()->password();
    auto gen = manager.credentials()->generation();
    auto pool = std::make_shared<ConnectionPool>(_pool_opts(4), _unreachable_opts("old"));
    REDIS_ASSERT(pool->connection_options().password == "old",
            "pool should start with explicit password");
    manager.register_pool(pool);
    REDIS_ASSERT(pool->connection_options().password == jwt,
            "register_pool should seed current JWT");
    REDIS_ASSERT(pool->password_generation() == gen,
            "register_pool should seed current generation");
    REDIS_ASSERT(manager.registered_pool_count() == 1,
            "registered pool should be counted");

    {
        bool thrown = false;
        try {
            std::shared_ptr<ConnectionPool> null_pool;
            manager.register_pool(null_pool);
        } catch (const Error &) {
            thrown = true;
        }
        REDIS_ASSERT(thrown, "register_pool should reject null pool");
    }

    {
        JwtAuthManager tmp(opts);
        {
            auto tmp_pool = std::make_shared<ConnectionPool>(_pool_opts(2), _unreachable_opts());
            tmp.register_pool(tmp_pool);
            REDIS_ASSERT(tmp.registered_pool_count() == 1,
                    "temporary pool should be registered");
        }
        tmp.refresh_now();
        REDIS_ASSERT(tmp.registered_pool_count() == 0,
                "expired pools should be pruned on refresh");
    }

    auto p1 = std::make_shared<ConnectionPool>(_pool_opts(2), _unreachable_opts());
    auto p2 = std::make_shared<ConnectionPool>(_pool_opts(2), _unreachable_opts());
    manager.register_pool(p1);
    manager.register_pool(p2);
    REDIS_ASSERT(manager.registered_pool_count() == 3, "should track multiple pools");
    manager.refresh_now();
    auto rotated = manager.credentials()->password();
    auto rotated_gen = manager.credentials()->generation();
    REDIS_ASSERT(p1->connection_options().password == rotated,
            "all pools should receive rotated password");
    REDIS_ASSERT(p2->connection_options().password == rotated,
            "all pools should receive rotated password");
    REDIS_ASSERT(p1->password_generation() == rotated_gen,
            "all pools should receive rotated generation");
    REDIS_ASSERT(p2->password_generation() == rotated_gen,
            "all pools should receive rotated generation");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_pool_password_update() {
    auto pool = std::make_shared<ConnectionPool>(_pool_opts(4), _unreachable_opts("p1"));
    pool->update_password("p2", 7);
    REDIS_ASSERT(pool->connection_options().password == "p2",
            "update_password should replace pool password");
    REDIS_ASSERT(pool->password_generation() == 7,
            "update_password should store generation");

    pool->update_password("rotated-jwt", 9);
    REDIS_ASSERT(pool->connection_options().password == "rotated-jwt",
            "new connections should use updated password options");
    REDIS_ASSERT(pool->password_generation() == 9,
            "new connections should use updated generation");

    bool create_failed = false;
    try {
        auto conn = pool->create();
        REDIS_ASSERT(conn.options().password == "rotated-jwt",
                "create should stamp latest password");
        REDIS_ASSERT(conn.password_generation() == 9,
                "create should stamp latest generation");
    } catch (const Error &) {
        create_failed = true;
    }
    REDIS_ASSERT(create_failed || pool->connection_options().password == "rotated-jwt",
            "unreachable host may fail create, options must stay updated");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_connection_helpers() {
    ConnectionPool pool(_pool_opts(2), _unreachable_opts("jwt-1"));
    pool.update_password("jwt-1", 3);
    _seed_idle_connections(pool, 1, "jwt-1", 3);
    REDIS_ASSERT(pool.idle_size() == 1, "should seed one idle connection");

    auto processed = pool.reauth_idle_connections(1, "jwt-2", 4, false);
    REDIS_ASSERT(processed == 1, "should process stale idle connection");
    REDIS_ASSERT(pool.idle_size() == 1, "processed connection should return to pool");

    auto broken = Connection::make_unconnected(_unreachable_opts("x"));
    REDIS_ASSERT(broken.broken(), "unconnected placeholder should be broken");
    bool thrown = false;
    try {
        broken.reauth("new-jwt");
    } catch (const Error &) {
        thrown = true;
    }
    REDIS_ASSERT(thrown, "reauth on broken connection should throw");

    ConnectionPool pool2(_pool_opts(2), _unreachable_opts("x"));
    _seed_idle_connections(pool2, 1, "x", 1);
    pool2.reauth_idle_connections(1, "new-jwt", 2, true);
    REDIS_ASSERT(pool2.idle_size() == 1,
            "inline reauth on broken idle connections should keep pool size stable");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_gradual_reauth() {
    ConnectionPool pool(_pool_opts(6), _unreachable_opts("old"));
    pool.update_password("old", 1);
    _seed_idle_connections(pool, 6, "old", 1);
    REDIS_ASSERT(pool.idle_size() == 6, "should seed full idle pool");

    auto n1 = pool.reauth_idle_connections(2, "new", 2, false);
    REDIS_ASSERT(n1 == 2, "first batch should process batch_size connections");
    REDIS_ASSERT(pool.idle_size() == 6, "batching must not drop the whole pool");

    auto n2 = pool.reauth_idle_connections(2, "new", 2, false);
    REDIS_ASSERT(n2 == 2, "second batch should continue rotation");
    auto n3 = pool.reauth_idle_connections(2, "new", 2, false);
    REDIS_ASSERT(n3 == 2, "third batch should finish rotation");
    auto n4 = pool.reauth_idle_connections(2, "new", 2, false);
    REDIS_ASSERT(n4 == 0, "no stale connections should remain");
    REDIS_ASSERT(pool.password_generation() == 1,
            "reauth_idle_connections should not implicitly call update_password");

    pool.update_password("new", 2);
    REDIS_ASSERT(pool.password_generation() == 2, "update_password should set generation");

    ConnectionPool tiny(_pool_opts(3), _unreachable_opts("a"));
    _seed_idle_connections(tiny, 1, "a", 1);
    REDIS_ASSERT(tiny.reauth_idle_connections(0, "b", 2, false) == 0,
            "zero batch size should be a no-op");
    REDIS_ASSERT(tiny.idle_size() == 1, "zero batch size should leave idle connections");

    ConnectionPool stale(_pool_opts(2), _unreachable_opts("v1"));
    stale.update_password("v1", 1);
    _seed_idle_connections(stale, 1, "v1", 1);
    stale.update_password("v2", 2);
    REDIS_ASSERT(stale.reauth_idle_connections(1, "v2", 2, false) == 1,
            "stale generation should be selected for rotation");
    REDIS_ASSERT(stale.reauth_idle_connections(1, "v2", 2, false) == 0,
            "rotated connections should not be selected again");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_manager_applies_to_pools() {
    auto counter = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions opts;
    opts.token_fetcher = [counter, this]() {
        counter->fetch_add(1);
        return _fake_jwt();
    };
    opts.refresh_interval = std::chrono::hours(1);
    opts.reauth_batch_size = 2;
    opts.reauth_batch_interval = std::chrono::milliseconds(1);
    opts.prefer_inline_reauth = false;

    JwtAuthManager manager(opts);
    auto pool = std::make_shared<ConnectionPool>(_pool_opts(5), _unreachable_opts());
    manager.register_pool(pool);
    _seed_idle_connections(*pool, 5, manager.credentials()->password(),
            manager.credentials()->generation());
    REDIS_ASSERT(pool->idle_size() == 5, "pool should keep seeded idle connections");

    auto before_gen = manager.credentials()->generation();
    manager.refresh_now();
    REDIS_ASSERT(pool->connection_options().password == manager.credentials()->password(),
            "refresh should push password to pool options");
    REDIS_ASSERT(pool->password_generation() == manager.credentials()->generation(),
            "refresh should push generation to pool");
    REDIS_ASSERT(manager.credentials()->generation() == before_gen + 1,
            "refresh should bump credentials generation");

    auto stale = pool->reauth_idle_connections(10, manager.credentials()->password(),
            manager.credentials()->generation(), false);
    REDIS_ASSERT(stale == 0, "all idle connections should be on the latest generation");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_background_refresh() {
    auto counter = std::make_shared<std::atomic<int>>(0);
    auto seen = std::make_shared<std::vector<std::string>>();
    auto seen_mu = std::make_shared<std::mutex>();

    JwtAuthOptions opts;
    opts.token_fetcher = [counter, seen, seen_mu, this]() {
        counter->fetch_add(1);
        auto token = _fake_jwt();
        {
            std::lock_guard<std::mutex> lock(*seen_mu);
            seen->push_back(token);
        }
        return token;
    };
    opts.refresh_interval = std::chrono::milliseconds(50);
    opts.reauth_batch_interval = std::chrono::milliseconds(0);
    opts.prefer_inline_reauth = false;

    JwtAuthManager manager(opts);
    auto pool = std::make_shared<ConnectionPool>(_pool_opts(2), _unreachable_opts());
    manager.register_pool(pool);
    REDIS_ASSERT(!manager.running(), "manager should not run before start");
    manager.start();
    REDIS_ASSERT(manager.running(), "manager should run after start");
    manager.start();
    REDIS_ASSERT(manager.running(), "start should be idempotent");

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (counter->load() < 3 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    REDIS_ASSERT(counter->load() >= 3, "background task should refresh periodically");
    REDIS_ASSERT(manager.refresh_count() >= 3, "refresh_count should increase in background");

    std::set<std::string> unique;
    {
        std::lock_guard<std::mutex> lock(*seen_mu);
        for (const auto &token : *seen) {
            unique.insert(token);
        }
    }
    REDIS_ASSERT(unique.size() >= 2, "background refresh should produce distinct JWTs");

    manager.stop();
    REDIS_ASSERT(!manager.running(), "manager should stop");
    auto count_after_stop = counter->load();
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    REDIS_ASSERT(counter->load() == count_after_stop,
            "token_fetcher should not run after stop");

    auto calls = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions resilient_opts;
    resilient_opts.token_fetcher = [calls, this]() {
        auto n = calls->fetch_add(1);
        if (n == 0) {
            return _fake_jwt();
        }
        if (n % 2 == 1) {
            throw std::runtime_error("transient");
        }
        return _fake_jwt();
    };
    resilient_opts.refresh_interval = std::chrono::milliseconds(30);
    resilient_opts.reauth_batch_interval = std::chrono::milliseconds(0);
    JwtAuthManager resilient(resilient_opts);
    resilient.start();
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (calls->load() < 5 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    resilient.stop();
    REDIS_ASSERT(calls->load() >= 5, "background refresh should survive fetcher errors");
    REDIS_ASSERT(!resilient.credentials()->password().empty(),
            "credentials should remain available after transient errors");

    auto zero_counter = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions zero_opts;
    zero_opts.token_fetcher = [zero_counter, this]() {
        zero_counter->fetch_add(1);
        return _fake_jwt();
    };
    zero_opts.refresh_interval = std::chrono::milliseconds(0);
    JwtAuthManager zero_manager(zero_opts);
    zero_manager.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    REDIS_ASSERT(zero_counter->load() == 1,
            "zero refresh_interval should disable periodic refresh");
    zero_manager.refresh_now();
    REDIS_ASSERT(zero_counter->load() == 2, "manual refresh_now should still work");
    zero_manager.stop();

    auto dtor_counter = std::make_shared<std::atomic<int>>(0);
    {
        JwtAuthOptions dtor_opts;
        dtor_opts.token_fetcher = [dtor_counter, this]() {
            dtor_counter->fetch_add(1);
            return _fake_jwt();
        };
        dtor_opts.refresh_interval = std::chrono::milliseconds(20);
        JwtAuthManager dtor_manager(dtor_opts);
        dtor_manager.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    auto after = dtor_counter->load();
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    REDIS_ASSERT(dtor_counter->load() == after,
            "destructor should stop background refresh thread");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_configurable_options() {
    JwtAuthOptions opts;
    opts.token_fetcher = [this]() { return _fake_jwt(); };
    opts.refresh_interval = std::chrono::minutes(4);
    opts.reauth_batch_size = 3;
    opts.reauth_batch_interval = std::chrono::milliseconds(25);
    opts.prefer_inline_reauth = false;
    JwtAuthManager manager(opts);
    REDIS_ASSERT(manager.options().refresh_interval == std::chrono::minutes(4),
            "refresh_interval should be configurable");
    REDIS_ASSERT(manager.options().reauth_batch_size == 3,
            "reauth_batch_size should be configurable");
    REDIS_ASSERT(manager.options().reauth_batch_interval == std::chrono::milliseconds(25),
            "reauth_batch_interval should be configurable");
    REDIS_ASSERT(!manager.options().prefer_inline_reauth,
            "prefer_inline_reauth should be configurable");
}

template <typename RedisInstance>
void JwtAuthTest<RedisInstance>::_test_concurrent_refresh() {
    auto counter = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions opts;
    opts.token_fetcher = [counter, this]() {
        counter->fetch_add(1);
        return _fake_jwt();
    };
    opts.refresh_interval = std::chrono::hours(1);
    opts.reauth_batch_interval = std::chrono::milliseconds(0);
    opts.prefer_inline_reauth = false;

    JwtAuthManager manager(opts);
    auto pool = std::make_shared<ConnectionPool>(_pool_opts(2), _unreachable_opts());
    manager.register_pool(pool);

    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&manager]() {
            for (int j = 0; j < 5; ++j) {
                manager.refresh_now();
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }

    REDIS_ASSERT(counter->load() == 1 + 20,
            "concurrent refresh_now calls should each fetch a token");
    REDIS_ASSERT(manager.refresh_count() == static_cast<std::size_t>(1 + 20),
            "refresh_count should match serialized fetches");
    REDIS_ASSERT(pool->password_generation() == manager.credentials()->generation(),
            "pool generation should match final credentials generation");
}

}

}

}

#endif // end SEWENEW_REDISPLUSPLUS_TEST_JWT_AUTH_TEST_HPP
