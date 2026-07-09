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

#include "sw/redis++/connection_pool.h"
#include <cassert>
#include <vector>
#include "sw/redis++/errors.h"

namespace sw {

namespace redis {

ConnectionPool::ConnectionPool(const ConnectionPoolOptions &pool_opts,
        const ConnectionOptions &connection_opts) :
            _opts(connection_opts),
            _pool_opts(pool_opts) {
    if (_pool_opts.size == 0) {
        throw Error("CANNOT create an empty pool");
    }

    // Lazily create connections.
}

ConnectionPool::ConnectionPool(SimpleSentinel sentinel,
                                const ConnectionPoolOptions &pool_opts,
                                const ConnectionOptions &connection_opts) :
                                    _opts(connection_opts),
                                    _pool_opts(pool_opts),
                                    _sentinel(std::move(sentinel)) {
    // In this case, the connection must be of TCP type.
    if (_opts.type != ConnectionType::TCP) {
        throw Error("Sentinel only supports TCP connection");
    }

    if (_opts.connect_timeout == std::chrono::milliseconds(0)
            || _opts.socket_timeout == std::chrono::milliseconds(0)) {
        throw Error("With sentinel, connection timeout and socket timeout cannot be 0");
    }

    // Cleanup connection options.
    _update_connection_opts("", -1);

    assert(_sentinel);
}

ConnectionPool::ConnectionPool(ConnectionPool &&that) {
    std::lock_guard<std::mutex> lock(that._mutex);

    _move(std::move(that));
}

ConnectionPool& ConnectionPool::operator=(ConnectionPool &&that) {
    if (this != &that) {
        std::lock(_mutex, that._mutex);
        std::lock_guard<std::mutex> lock_this(_mutex, std::adopt_lock);
        std::lock_guard<std::mutex> lock_that(that._mutex, std::adopt_lock);

        _move(std::move(that));
    }

    return *this;
}

Connection ConnectionPool::fetch() {
    std::unique_lock<std::mutex> lock(_mutex);

    auto connection = _fetch(lock);

    auto connection_lifetime = _pool_opts.connection_lifetime;
    auto connection_idle_time = _pool_opts.connection_idle_time;
    auto password_generation = _password_generation;

    if (_sentinel) {
        auto opts = _opts;
        auto role_changed = _role_changed(connection.options());
        auto sentinel = _sentinel;

        lock.unlock();

        if (role_changed || _need_reconnect(connection, connection_lifetime, connection_idle_time)) {
            try {
                connection = _create(sentinel, opts);
                connection.set_password_generation(password_generation);
            } catch (const Error &) {
                // Failed to reconnect, return it to the pool, and retry latter.
                release(std::move(connection));
                throw;
            }
        } else {
            _ensure_fresh_credentials(connection);
        }

        return connection;
    }

    auto opts = _opts;
    lock.unlock();

    if (_need_reconnect(connection, connection_lifetime, connection_idle_time)) {
        try {
            // Ensure reconnect uses the latest password from the pool options.
            connection.set_password(opts.password);
            connection.set_password_generation(password_generation);
            connection.reconnect();
        } catch (const Error &) {
            // Failed to reconnect, return it to the pool, and retry latter.
            release(std::move(connection));
            throw;
        }
    } else {
        _ensure_fresh_credentials(connection);
    }

    return connection;
}

ConnectionOptions ConnectionPool::connection_options() {
    std::lock_guard<std::mutex> lock(_mutex);

    return _opts;
}

void ConnectionPool::release(Connection connection) {
    {
        std::lock_guard<std::mutex> lock(_mutex);

        _pool.push_back(std::move(connection));
    }

    _cv.notify_one();
}

Connection ConnectionPool::create() {
    std::unique_lock<std::mutex> lock(_mutex);

    auto opts = _opts;
    auto password_generation = _password_generation;

    if (_sentinel) {
        auto sentinel = _sentinel;

        lock.unlock();

        auto connection = _create(sentinel, opts);
        connection.set_password_generation(password_generation);
        return connection;
    } else {
        lock.unlock();

        Connection connection(opts);
        connection.set_password_generation(password_generation);
        return connection;
    }
}

void ConnectionPool::update_password(std::string password, std::uint64_t generation) {
    std::lock_guard<std::mutex> lock(_mutex);
    _opts.password = std::move(password);
    _password_generation = generation;
}

std::uint64_t ConnectionPool::password_generation() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _password_generation;
}

std::size_t ConnectionPool::reauth_idle_connections(std::size_t batch_size,
                                                    const std::string &password,
                                                    std::uint64_t generation,
                                                    bool inline_reauth) {
    if (batch_size == 0) {
        return 0;
    }

    std::vector<Connection> batch;
    batch.reserve(batch_size);

    {
        std::lock_guard<std::mutex> lock(_mutex);
        while (batch.size() < batch_size && !_pool.empty()) {
            // Prefer connections that still need a credential rotation.
            auto it = _pool.begin();
            for (; it != _pool.end(); ++it) {
                if (generation != 0 && it->password_generation() != generation) {
                    break;
                }
                if (generation == 0 && it->options().password != password) {
                    break;
                }
            }
            if (it == _pool.end()) {
                break;
            }
            batch.push_back(std::move(*it));
            _pool.erase(it);
        }
    }

    std::size_t processed = 0;
    for (auto &connection : batch) {
        if (connection.broken()) {
            // Leave broken; reconnect path on next fetch will use new password.
            connection.set_password(password);
            connection.set_password_generation(generation);
            release(std::move(connection));
            ++processed;
            continue;
        }

        if (inline_reauth) {
            try {
                connection.reauth(password);
                connection.set_password_generation(generation);
            } catch (const Error &) {
                // AUTH failed (e.g. server closed the connection). Invalidate so
                // the next borrower reconnects with the updated password.
                connection.set_password(password);
                connection.set_password_generation(generation);
                connection.invalidate();
            }
        } else {
            // Soft drop: mark broken without closing every connection at once.
            // Caller is expected to process the pool in small batches.
            connection.set_password(password);
            connection.set_password_generation(generation);
            connection.invalidate();
        }

        release(std::move(connection));
        ++processed;
    }

    return processed;
}

std::size_t ConnectionPool::idle_size() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _pool.size();
}

ConnectionPool ConnectionPool::clone() {
    std::unique_lock<std::mutex> lock(_mutex);

    auto opts = _opts;
    auto pool_opts = _pool_opts;

    if (_sentinel) {
        auto sentinel = _sentinel;

        lock.unlock();

        return ConnectionPool(sentinel, pool_opts, opts);
    } else {
        lock.unlock();

        return ConnectionPool(pool_opts, opts);
    }
}

void ConnectionPool::_move(ConnectionPool &&that) {
    _opts = std::move(that._opts);
    _pool_opts = std::move(that._pool_opts);
    _pool = std::move(that._pool);
    _used_connections = that._used_connections;
    _password_generation = that._password_generation;
    _sentinel = std::move(that._sentinel);
}

Connection ConnectionPool::_create(SimpleSentinel &sentinel,
                                    const ConnectionOptions &opts) {
    auto connection = sentinel.create(opts);

    std::lock_guard<std::mutex> lock(_mutex);

    const auto &connection_opts = connection.options();
    if (_role_changed(connection_opts)) {
        // Master/Slave has been changed, reconnect all connections.
        _update_connection_opts(connection_opts.host, connection_opts.port);
    }

    return connection;
}

Connection ConnectionPool::_fetch(std::unique_lock<std::mutex> &lock) {
    if (_pool.empty()) {
        if (_used_connections == _pool_opts.size) {
            _wait_for_connection(lock);
        } else {
            ++_used_connections;

            // Lazily create a new (broken) connection to avoid connecting with lock.
            return Connection(_opts, Connection::Dummy{});
        }
    }

    // _pool is NOT empty.
    return _fetch();
}

Connection ConnectionPool::_fetch() {
    assert(!_pool.empty());

    auto connection = std::move(_pool.front());
    _pool.pop_front();

    return connection;
}

void ConnectionPool::_wait_for_connection(std::unique_lock<std::mutex> &lock) {
    auto timeout = _pool_opts.wait_timeout;
    if (timeout > std::chrono::milliseconds(0)) {
        // Wait until _pool is no longer empty or timeout.
        if (!_cv.wait_for(lock,
                    timeout,
                    [this] { return !(this->_pool).empty(); })) {
            throw Error("Failed to fetch a connection in "
                    + std::to_string(timeout.count()) + " milliseconds");
        }
    } else {
        // Wait forever.
        _cv.wait(lock, [this] { return !(this->_pool).empty(); });
    }
}

bool ConnectionPool::_need_reconnect(const Connection &connection,
                                    const std::chrono::milliseconds &connection_lifetime,
                                    const std::chrono::milliseconds &connection_idle_time) const {
    if (connection.broken()) {
        return true;
    }

    auto now = std::chrono::steady_clock::now();
    if (connection_lifetime > std::chrono::milliseconds(0)) {
        if (now - connection.create_time() > connection_lifetime) {
            return true;
        }
    }

    if (connection_idle_time > std::chrono::milliseconds(0)) {
        if (now - connection.last_active() > connection_idle_time) {
            return true;
        }
    }

    return false;
}

void ConnectionPool::_ensure_fresh_credentials(Connection &connection) {
    std::string password;
    std::uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_password_generation == 0 ||
                connection.password_generation() == _password_generation) {
            return;
        }
        password = _opts.password;
        generation = _password_generation;
    }

    if (connection.broken()) {
        connection.set_password(password);
        connection.set_password_generation(generation);
        return;
    }

    try {
        connection.reauth(password);
        connection.set_password_generation(generation);
    } catch (const Error &) {
        connection.set_password(password);
        connection.set_password_generation(generation);
        connection.invalidate();
        // Reconnect with the new password so the borrower still gets a usable connection.
        connection.reconnect();
    }
}

}

}
