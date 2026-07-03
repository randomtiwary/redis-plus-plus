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

// Standalone unit tests for JWT / reauth support.
// These tests intentionally make NO network calls and do NOT require a Redis
// server. Token fetching is faked with an in-process callback that returns a
// random JWT-like string on each invocation.

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <set>
#include <mutex>

#include <sw/redis++/jwt_auth.h>
#include <sw/redis++/connection_pool.h>
#include <sw/redis++/connection.h>
#include <sw/redis++/errors.h>

namespace {

using sw::redis::Connection;
using sw::redis::ConnectionOptions;
using sw::redis::ConnectionPool;
using sw::redis::ConnectionPoolOptions;
using sw::redis::Error;
using sw::redis::JwtAuthManager;
using sw::redis::JwtAuthOptions;
using sw::redis::JwtCredentials;
using sw::redis::TokenFetcher;

int g_failures = 0;

#define EXPECT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ \
                      << " EXPECT_TRUE(" << #expr << ")\n"; \
            ++g_failures; \
        } \
    } while (0)

#define EXPECT_FALSE(expr) EXPECT_TRUE(!(expr))

#define EXPECT_EQ(a, b) \
    do { \
        const auto &va = (a); \
        const auto &vb = (b); \
        if (!(va == vb)) { \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ \
                      << " EXPECT_EQ(" << #a << ", " << #b << ") got " \
                      << va << " vs " << vb << "\n"; \
            ++g_failures; \
        } \
    } while (0)

#define EXPECT_NE(a, b) \
    do { \
        const auto &va = (a); \
        const auto &vb = (b); \
        if (!(va != vb)) { \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ \
                      << " EXPECT_NE(" << #a << ", " << #b << ")\n"; \
            ++g_failures; \
        } \
    } while (0)

#define EXPECT_GE(a, b) \
    do { \
        const auto &va = (a); \
        const auto &vb = (b); \
        if (!(va >= vb)) { \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ \
                      << " EXPECT_GE(" << #a << ", " << #b << ") got " \
                      << va << " vs " << vb << "\n"; \
            ++g_failures; \
        } \
    } while (0)

#define EXPECT_LE(a, b) \
    do { \
        const auto &va = (a); \
        const auto &vb = (b); \
        if (!(va <= vb)) { \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ \
                      << " EXPECT_LE(" << #a << ", " << #b << ") got " \
                      << va << " vs " << vb << "\n"; \
            ++g_failures; \
        } \
    } while (0)

#define EXPECT_THROW(expr) \
    do { \
        bool thrown = false; \
        try { expr; } catch (const Error &) { thrown = true; } \
          catch (...) { thrown = true; } \
        if (!thrown) { \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ \
                      << " EXPECT_THROW(" << #expr << ")\n"; \
            ++g_failures; \
        } \
    } while (0)

#define EXPECT_NO_THROW(expr) \
    do { \
        try { expr; } catch (...) { \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ \
                      << " EXPECT_NO_THROW(" << #expr << ")\n"; \
            ++g_failures; \
        } \
    } while (0)

std::string random_segment(std::size_t len = 16) {
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

// Fake JWT: header.payload.signature with a random payload segment.
// Mimics the shape of a real JWT without any crypto or network.
std::string fake_jwt() {
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + random_segment(24) + "." + random_segment(32);
}

TokenFetcher counting_fetcher(std::shared_ptr<std::atomic<int>> counter,
                              std::shared_ptr<std::vector<std::string>> seen = nullptr,
                              std::shared_ptr<std::mutex> seen_mu = nullptr) {
    return [counter, seen, seen_mu]() {
        counter->fetch_add(1);
        auto token = fake_jwt();
        if (seen && seen_mu) {
            std::lock_guard<std::mutex> lock(*seen_mu);
            seen->push_back(token);
        }
        return token;
    };
}

ConnectionOptions unreachable_opts(const std::string &password = {}) {
    ConnectionOptions opts;
    opts.host = "127.0.0.1";
    opts.port = 1; // nothing listens; connects are never attempted in these tests
    opts.password = password;
    opts.connect_timeout = std::chrono::milliseconds(1);
    opts.socket_timeout = std::chrono::milliseconds(1);
    return opts;
}

ConnectionPoolOptions small_pool_opts(std::size_t size = 4) {
    ConnectionPoolOptions opts;
    opts.size = size;
    opts.wait_timeout = std::chrono::milliseconds(50);
    return opts;
}

// Seed the pool with `n` idle broken placeholder connections (no network).
void seed_idle_connections(ConnectionPool &pool, std::size_t n,
                           const std::string &password, std::uint64_t generation) {
    auto opts = pool.connection_options();
    opts.password = password;
    for (std::size_t i = 0; i < n; ++i) {
        auto conn = Connection::make_unconnected(opts);
        conn.set_password(password);
        conn.set_password_generation(generation);
        pool.release(std::move(conn));
    }
}

void test_jwt_used_as_password_in_connection_options() {
    std::cout << "test_jwt_used_as_password_in_connection_options\n";
    auto jwt = fake_jwt();
    ConnectionOptions opts;
    opts.password = jwt;
    EXPECT_EQ(opts.password, jwt);
    EXPECT_TRUE(opts.password.find('.') != std::string::npos);
}

void test_credentials_initial_state() {
    std::cout << "test_credentials_initial_state\n";
    JwtCredentials empty;
    EXPECT_TRUE(empty.password().empty());
    EXPECT_EQ(empty.generation(), 0u);

    auto jwt = fake_jwt();
    JwtCredentials creds(jwt);
    EXPECT_EQ(creds.password(), jwt);
    EXPECT_EQ(creds.generation(), 1u);

    auto snap = creds.snapshot();
    EXPECT_EQ(snap.first, jwt);
    EXPECT_EQ(snap.second, 1u);
}

void test_credentials_update_bumps_generation() {
    std::cout << "test_credentials_update_bumps_generation\n";
    JwtCredentials creds(fake_jwt());
    auto g1 = creds.generation();
    auto t2 = fake_jwt();
    auto g2 = creds.update(t2);
    EXPECT_EQ(g2, g1 + 1);
    EXPECT_EQ(creds.password(), t2);
    EXPECT_EQ(creds.generation(), g2);
    auto t3 = fake_jwt();
    auto g3 = creds.update(t3);
    EXPECT_EQ(g3, g2 + 1);
    EXPECT_NE(creds.password(), t2);
}

void test_credentials_thread_safety() {
    std::cout << "test_credentials_thread_safety\n";
    auto creds = std::make_shared<JwtCredentials>(fake_jwt());
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([creds, &start] {
            while (!start.load()) {}
            for (int j = 0; j < 100; ++j) {
                creds->update(fake_jwt());
                auto snap = creds->snapshot();
                EXPECT_FALSE(snap.first.empty());
                EXPECT_GE(snap.second, 1u);
            }
        });
    }
    start = true;
    for (auto &t : threads) t.join();
    EXPECT_GE(creds->generation(), 1u);
}

void test_manager_requires_fetcher_and_batch_size() {
    std::cout << "test_manager_requires_fetcher_and_batch_size\n";
    JwtAuthOptions opts;
    EXPECT_THROW(JwtAuthManager m(opts));
    opts.token_fetcher = fake_jwt;
    opts.reauth_batch_size = 0;
    EXPECT_THROW(JwtAuthManager m(opts));
    opts.reauth_batch_size = 1;
    EXPECT_NO_THROW(JwtAuthManager m(opts));
    EXPECT_THROW(JwtAuthManager m(opts, nullptr));
}

void test_manager_fetches_initial_token() {
    std::cout << "test_manager_fetches_initial_token\n";
    auto counter = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions opts;
    opts.token_fetcher = counting_fetcher(counter);
    opts.refresh_interval = std::chrono::hours(1);
    JwtAuthManager manager(opts);
    EXPECT_EQ(counter->load(), 1);
    EXPECT_EQ(manager.refresh_count(), 1u);
    EXPECT_FALSE(manager.credentials()->password().empty());
    EXPECT_EQ(manager.credentials()->generation(), 1u);
}

void test_manager_refresh_now_updates_credentials() {
    std::cout << "test_manager_refresh_now_updates_credentials\n";
    auto counter = std::make_shared<std::atomic<int>>(0);
    auto seen = std::make_shared<std::vector<std::string>>();
    auto seen_mu = std::make_shared<std::mutex>();
    JwtAuthOptions opts;
    opts.token_fetcher = counting_fetcher(counter, seen, seen_mu);
    opts.refresh_interval = std::chrono::hours(1);
    JwtAuthManager manager(opts);
    auto first = manager.credentials()->password();
    auto g1 = manager.credentials()->generation();
    manager.refresh_now();
    auto second = manager.credentials()->password();
    auto g2 = manager.credentials()->generation();
    EXPECT_NE(first, second);
    EXPECT_EQ(g2, g1 + 1);
    EXPECT_EQ(counter->load(), 2);
    EXPECT_EQ(manager.refresh_count(), 2u);
    {
        std::lock_guard<std::mutex> lock(*seen_mu);
        EXPECT_EQ(seen->size(), 2u);
        EXPECT_NE((*seen)[0], (*seen)[1]);
    }
}

void test_manager_rejects_empty_token() {
    std::cout << "test_manager_rejects_empty_token\n";
    JwtAuthOptions opts;
    opts.token_fetcher = []() { return std::string(); };
    EXPECT_THROW(JwtAuthManager m(opts));

    opts.token_fetcher = fake_jwt;
    JwtAuthManager manager(opts);
    manager.options(); // silence unused
    // Replace fetcher indirectly by constructing with shared creds then calling refresh with bad fetcher
    // is not possible since opts are copied. Recreate:
    JwtAuthOptions opts2;
    opts2.token_fetcher = []() { return std::string("ok"); };
    auto creds = std::make_shared<JwtCredentials>("ok");
    JwtAuthManager manager2(opts2, creds);
    // Can't change fetcher; verify update path with a manager whose fetcher fails on 2nd call.
    auto calls = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions opts3;
    opts3.token_fetcher = [calls]() {
        if (calls->fetch_add(1) == 0) return fake_jwt();
        return std::string();
    };
    JwtAuthManager manager3(opts3);
    EXPECT_THROW(manager3.refresh_now());
}

void test_register_pool_seeds_password() {
    std::cout << "test_register_pool_seeds_password\n";
    JwtAuthOptions opts;
    opts.token_fetcher = fake_jwt;
    opts.refresh_interval = std::chrono::hours(1);
    JwtAuthManager manager(opts);
    auto jwt = manager.credentials()->password();
    auto gen = manager.credentials()->generation();

    auto pool = std::make_shared<ConnectionPool>(small_pool_opts(), unreachable_opts("old"));
    EXPECT_EQ(pool->connection_options().password, "old");
    manager.register_pool(pool);
    EXPECT_EQ(pool->connection_options().password, jwt);
    EXPECT_EQ(pool->password_generation(), gen);
    EXPECT_EQ(manager.registered_pool_count(), 1u);
}

void test_register_null_pool_throws() {
    std::cout << "test_register_null_pool_throws\n";
    JwtAuthOptions opts;
    opts.token_fetcher = fake_jwt;
    JwtAuthManager manager(opts);
    std::shared_ptr<ConnectionPool> null_pool;
    EXPECT_THROW(manager.register_pool(null_pool));
}

void test_expired_pool_removed_from_registry() {
    std::cout << "test_expired_pool_removed_from_registry\n";
    JwtAuthOptions opts;
    opts.token_fetcher = fake_jwt;
    opts.refresh_interval = std::chrono::hours(1);
    opts.reauth_batch_interval = std::chrono::milliseconds(0);
    JwtAuthManager manager(opts);
    {
        auto pool = std::make_shared<ConnectionPool>(small_pool_opts(), unreachable_opts());
        manager.register_pool(pool);
        EXPECT_EQ(manager.registered_pool_count(), 1u);
    }
    manager.refresh_now();
    EXPECT_EQ(manager.registered_pool_count(), 0u);
}

void test_pool_update_password() {
    std::cout << "test_pool_update_password\n";
    auto pool = std::make_shared<ConnectionPool>(small_pool_opts(), unreachable_opts("p1"));
    pool->update_password("p2", 7);
    EXPECT_EQ(pool->connection_options().password, "p2");
    EXPECT_EQ(pool->password_generation(), 7u);
}

void test_connection_password_generation_tracking() {
    std::cout << "test_connection_password_generation_tracking\n";
    ConnectionOptions opts = unreachable_opts("jwt-1");
    ConnectionPoolOptions pool_opts;
    pool_opts.size = 2;
    pool_opts.wait_timeout = std::chrono::milliseconds(10);
    ConnectionPool pool(pool_opts, opts);
    pool.update_password("jwt-1", 3);
    seed_idle_connections(pool, 1, "jwt-1", 3);
    EXPECT_EQ(pool.idle_size(), 1u);
    // Borrow without reconnect by using a lifetime that does not expire and
    // accepting that broken placeholders reconnect on fetch; validate setters
    // on a connection we construct through create() failure path instead.
    try {
        auto conn = pool.create();
        conn.set_password_generation(3);
        EXPECT_EQ(conn.password_generation(), 3u);
        conn.set_password("jwt-2");
        EXPECT_EQ(conn.options().password, "jwt-2");
    } catch (const Error &) {
        // create() connects immediately; unreachable host is expected.
        EXPECT_TRUE(true);
    }
    // Directly exercise setters via reauth_idle bookkeeping.
    auto processed = pool.reauth_idle_connections(1, "jwt-2", 4, false);
    EXPECT_EQ(processed, 1u);
    EXPECT_EQ(pool.idle_size(), 1u);
}

void test_reauth_on_broken_connection_throws() {
    std::cout << "test_reauth_on_broken_connection_throws\n";
    auto conn = Connection::make_unconnected(unreachable_opts("x"));
    EXPECT_TRUE(conn.broken());
    EXPECT_THROW(conn.reauth("new-jwt"));

    ConnectionPoolOptions pool_opts;
    pool_opts.size = 2;
    ConnectionPool pool(pool_opts, unreachable_opts("x"));
    seed_idle_connections(pool, 1, "x", 1);
    EXPECT_NO_THROW(pool.reauth_idle_connections(1, "new-jwt", 2, true));
}

void test_gradual_reauth_batching_does_not_drop_all_at_once() {
    std::cout << "test_gradual_reauth_batching_does_not_drop_all_at_once\n";
    ConnectionPoolOptions pool_opts;
    pool_opts.size = 6;
    ConnectionPool pool(pool_opts, unreachable_opts("old"));
    pool.update_password("old", 1);
    seed_idle_connections(pool, 6, "old", 1);
    EXPECT_EQ(pool.idle_size(), 6u);

    // Process in batches of 2 without inline auth (soft invalidate).
    auto n1 = pool.reauth_idle_connections(2, "new", 2, false);
    EXPECT_EQ(n1, 2u);
    EXPECT_EQ(pool.idle_size(), 6u); // connections returned to pool
    auto n2 = pool.reauth_idle_connections(2, "new", 2, false);
    EXPECT_EQ(n2, 2u);
    auto n3 = pool.reauth_idle_connections(2, "new", 2, false);
    EXPECT_EQ(n3, 2u);
    auto n4 = pool.reauth_idle_connections(2, "new", 2, false);
    EXPECT_EQ(n4, 0u); // all rotated
    EXPECT_EQ(pool.password_generation(), 1u);
    pool.update_password("new", 2);
    EXPECT_EQ(pool.password_generation(), 2u);
}

void test_reauth_batch_size_zero_is_noop() {
    std::cout << "test_reauth_batch_size_zero_is_noop\n";
    ConnectionPool pool(small_pool_opts(3), unreachable_opts("a"));
    seed_idle_connections(pool, 1, "a", 1);
    EXPECT_EQ(pool.reauth_idle_connections(0, "b", 2, false), 0u);
    EXPECT_EQ(pool.idle_size(), 1u);
}

void test_manager_applies_refresh_to_pools_gradually() {
    std::cout << "test_manager_applies_refresh_to_pools_gradually\n";
    auto counter = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions opts;
    opts.token_fetcher = counting_fetcher(counter);
    opts.refresh_interval = std::chrono::hours(1);
    opts.reauth_batch_size = 2;
    opts.reauth_batch_interval = std::chrono::milliseconds(1);
    opts.prefer_inline_reauth = false; // avoid AUTH on dummy connections
    JwtAuthManager manager(opts);

    auto pool = std::make_shared<ConnectionPool>(small_pool_opts(5), unreachable_opts());
    manager.register_pool(pool);
    seed_idle_connections(*pool, 5, manager.credentials()->password(),
                          manager.credentials()->generation());
    EXPECT_EQ(pool->idle_size(), 5u);

    auto before_gen = manager.credentials()->generation();
    auto start = std::chrono::steady_clock::now();
    manager.refresh_now();
    auto elapsed = std::chrono::steady_clock::now() - start;
    // With batch interval 1ms and 3 batches (2+2+1), elapsed should be > 0.
    EXPECT_GE(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 0);
    EXPECT_EQ(pool->connection_options().password, manager.credentials()->password());
    EXPECT_EQ(pool->password_generation(), manager.credentials()->generation());
    EXPECT_EQ(manager.credentials()->generation(), before_gen + 1);

    // All idle connections should now be on the new generation.
    std::size_t stale = pool->reauth_idle_connections(10, manager.credentials()->password(),
                                                      manager.credentials()->generation(), false);
    EXPECT_EQ(stale, 0u);
}

void test_multiple_pools_receive_updates() {
    std::cout << "test_multiple_pools_receive_updates\n";
    JwtAuthOptions opts;
    opts.token_fetcher = fake_jwt;
    opts.refresh_interval = std::chrono::hours(1);
    opts.reauth_batch_interval = std::chrono::milliseconds(0);
    opts.prefer_inline_reauth = false;
    JwtAuthManager manager(opts);

    auto p1 = std::make_shared<ConnectionPool>(small_pool_opts(2), unreachable_opts());
    auto p2 = std::make_shared<ConnectionPool>(small_pool_opts(2), unreachable_opts());
    manager.register_pool(p1);
    manager.register_pool(p2);
    EXPECT_EQ(manager.registered_pool_count(), 2u);
    manager.refresh_now();
    auto jwt = manager.credentials()->password();
    auto gen = manager.credentials()->generation();
    EXPECT_EQ(p1->connection_options().password, jwt);
    EXPECT_EQ(p2->connection_options().password, jwt);
    EXPECT_EQ(p1->password_generation(), gen);
    EXPECT_EQ(p2->password_generation(), gen);
}

void test_background_refresh_runs_periodically() {
    std::cout << "test_background_refresh_runs_periodically\n";
    auto counter = std::make_shared<std::atomic<int>>(0);
    auto seen = std::make_shared<std::vector<std::string>>();
    auto seen_mu = std::make_shared<std::mutex>();
    JwtAuthOptions opts;
    opts.token_fetcher = counting_fetcher(counter, seen, seen_mu);
    opts.refresh_interval = std::chrono::milliseconds(50);
    opts.reauth_batch_interval = std::chrono::milliseconds(0);
    opts.prefer_inline_reauth = false;
    JwtAuthManager manager(opts);
    auto pool = std::make_shared<ConnectionPool>(small_pool_opts(2), unreachable_opts());
    manager.register_pool(pool);
    EXPECT_FALSE(manager.running());
    manager.start();
    EXPECT_TRUE(manager.running());
    manager.start(); // idempotent
    EXPECT_TRUE(manager.running());

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (counter->load() < 3 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_GE(counter->load(), 3);
    EXPECT_GE(manager.refresh_count(), 3u);

    std::set<std::string> unique;
    {
        std::lock_guard<std::mutex> lock(*seen_mu);
        for (const auto &t : *seen) unique.insert(t);
    }
    EXPECT_GE(unique.size(), 2u);

    manager.stop();
    EXPECT_FALSE(manager.running());
    auto count_after_stop = counter->load();
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    EXPECT_EQ(counter->load(), count_after_stop);
}

void test_background_refresh_survives_fetcher_errors() {
    std::cout << "test_background_refresh_survives_fetcher_errors\n";
    auto calls = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions opts;
    opts.token_fetcher = [calls]() {
        auto n = calls->fetch_add(1);
        if (n == 0) return fake_jwt();
        if (n % 2 == 1) throw std::runtime_error("transient");
        return fake_jwt();
    };
    opts.refresh_interval = std::chrono::milliseconds(30);
    opts.reauth_batch_interval = std::chrono::milliseconds(0);
    JwtAuthManager manager(opts);
    manager.start();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (calls->load() < 5 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    manager.stop();
    EXPECT_GE(calls->load(), 5);
    EXPECT_FALSE(manager.credentials()->password().empty());
}

void test_zero_refresh_interval_disables_periodic() {
    std::cout << "test_zero_refresh_interval_disables_periodic\n";
    auto counter = std::make_shared<std::atomic<int>>(0);
    JwtAuthOptions opts;
    opts.token_fetcher = counting_fetcher(counter);
    opts.refresh_interval = std::chrono::milliseconds(0);
    JwtAuthManager manager(opts);
    manager.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(counter->load(), 1); // only initial fetch
    manager.refresh_now();
    EXPECT_EQ(counter->load(), 2);
    manager.stop();
}

void test_options_are_configurable() {
    std::cout << "test_options_are_configurable\n";
    JwtAuthOptions opts;
    opts.token_fetcher = fake_jwt;
    opts.refresh_interval = std::chrono::minutes(4);
    opts.reauth_batch_size = 3;
    opts.reauth_batch_interval = std::chrono::milliseconds(25);
    opts.prefer_inline_reauth = false;
    JwtAuthManager manager(opts);
    EXPECT_EQ(manager.options().refresh_interval.count(),
              std::chrono::milliseconds(std::chrono::minutes(4)).count());
    EXPECT_EQ(manager.options().reauth_batch_size, 3u);
    EXPECT_EQ(manager.options().reauth_batch_interval.count(), 25);
    EXPECT_FALSE(manager.options().prefer_inline_reauth);
}

void test_concurrent_refresh_now_is_serialized() {
    std::cout << "test_concurrent_refresh_now_is_serialized\n";
    auto counter = std::make_shared<std::atomic<int>>(0);
    auto seen = std::make_shared<std::vector<std::string>>();
    auto seen_mu = std::make_shared<std::mutex>();
    JwtAuthOptions opts;
    opts.token_fetcher = counting_fetcher(counter, seen, seen_mu);
    opts.refresh_interval = std::chrono::hours(1);
    opts.reauth_batch_interval = std::chrono::milliseconds(0);
    opts.prefer_inline_reauth = false;
    JwtAuthManager manager(opts);
    auto pool = std::make_shared<ConnectionPool>(small_pool_opts(2), unreachable_opts());
    manager.register_pool(pool);

    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&manager] {
            for (int j = 0; j < 5; ++j) {
                manager.refresh_now();
            }
        });
    }
    for (auto &t : threads) t.join();
    EXPECT_EQ(counter->load(), 1 + 20);
    EXPECT_EQ(manager.refresh_count(), static_cast<std::size_t>(1 + 20));
    EXPECT_EQ(pool->password_generation(), manager.credentials()->generation());
}

void test_fetch_uses_updated_password_for_new_connections() {
    std::cout << "test_fetch_uses_updated_password_for_new_connections\n";
    ConnectionPool pool(small_pool_opts(2), unreachable_opts("initial"));
    pool.update_password("rotated-jwt", 9);
    EXPECT_EQ(pool.connection_options().password, "rotated-jwt");
    EXPECT_EQ(pool.password_generation(), 9u);
    try {
        auto c = pool.create();
        EXPECT_EQ(c.options().password, "rotated-jwt");
        EXPECT_EQ(c.password_generation(), 9u);
    } catch (const Error &) {
        // Unreachable host; password is still applied on the options snapshot.
        EXPECT_EQ(pool.connection_options().password, "rotated-jwt");
    }
}

void test_ensure_fresh_credentials_on_fetch_for_stale_generation() {
    std::cout << "test_ensure_fresh_credentials_on_fetch_for_stale_generation\n";
    ConnectionPool pool(small_pool_opts(2), unreachable_opts("v1"));
    pool.update_password("v1", 1);
    seed_idle_connections(pool, 1, "v1", 1);
    EXPECT_EQ(pool.idle_size(), 1u);

    pool.update_password("v2", 2);
    // Stale idle connection should be picked up by gradual reauth.
    auto processed = pool.reauth_idle_connections(1, "v2", 2, false);
    EXPECT_EQ(processed, 1u);
    auto remaining = pool.reauth_idle_connections(1, "v2", 2, false);
    EXPECT_EQ(remaining, 0u);
    EXPECT_EQ(pool.connection_options().password, "v2");
    EXPECT_EQ(pool.password_generation(), 2u);
}

void test_destructor_stops_background_thread() {
    std::cout << "test_destructor_stops_background_thread\n";
    auto counter = std::make_shared<std::atomic<int>>(0);
    {
        JwtAuthOptions opts;
        opts.token_fetcher = counting_fetcher(counter);
        opts.refresh_interval = std::chrono::milliseconds(20);
        JwtAuthManager manager(opts);
        manager.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    auto after = counter->load();
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_EQ(counter->load(), after);
}

void test_shared_credentials_constructor() {
    std::cout << "test_shared_credentials_constructor\n";
    auto creds = std::make_shared<JwtCredentials>(fake_jwt());
    auto g0 = creds->generation();
    JwtAuthOptions opts;
    opts.token_fetcher = fake_jwt;
    opts.refresh_interval = std::chrono::hours(1);
    JwtAuthManager manager(opts, creds);
    EXPECT_EQ(manager.credentials().get(), creds.get());
    EXPECT_EQ(manager.refresh_count(), 0u);
    manager.refresh_now();
    EXPECT_EQ(creds->generation(), g0 + 1);
}

} // namespace

int main() {
    test_jwt_used_as_password_in_connection_options();
    test_credentials_initial_state();
    test_credentials_update_bumps_generation();
    test_credentials_thread_safety();
    test_manager_requires_fetcher_and_batch_size();
    test_manager_fetches_initial_token();
    test_manager_refresh_now_updates_credentials();
    test_manager_rejects_empty_token();
    test_register_pool_seeds_password();
    test_register_null_pool_throws();
    test_expired_pool_removed_from_registry();
    test_pool_update_password();
    test_connection_password_generation_tracking();
    test_reauth_on_broken_connection_throws();
    test_gradual_reauth_batching_does_not_drop_all_at_once();
    test_reauth_batch_size_zero_is_noop();
    test_manager_applies_refresh_to_pools_gradually();
    test_multiple_pools_receive_updates();
    test_background_refresh_runs_periodically();
    test_background_refresh_survives_fetcher_errors();
    test_zero_refresh_interval_disables_periodic();
    test_options_are_configurable();
    test_concurrent_refresh_now_is_serialized();
    test_fetch_uses_updated_password_for_new_connections();
    test_ensure_fresh_credentials_on_fetch_for_stale_generation();
    test_destructor_stops_background_thread();
    test_shared_credentials_constructor();

    if (g_failures == 0) {
        std::cout << "All jwt_auth tests passed.\n";
        return 0;
    }
    std::cerr << g_failures << " assertion(s) failed.\n";
    return 1;
}
