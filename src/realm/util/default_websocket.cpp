/*************************************************************************
 *
 * Copyright 2022 Realm Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **************************************************************************/

#include <realm/util/default_websocket.hpp>

#include <realm/util/websocket.hpp>
#include <realm/util/network_ssl.hpp>

namespace realm::util::websocket {

namespace {
class LegacyWebsocketImpl final : public WebSocket, public realm::util::websocket::Config {
public:
    LegacyWebsocketImpl(const SocketFactoryConfig& config, const DefaultSocketFactoryConfig& legacy_config,
               SocketObserver& observer, Endpoint&& endpoint)
        : m_config(config)
        , m_legacy_config(legacy_config)
        , m_observer(observer)
        , m_endpoint(std::move(endpoint))
        , m_websocket(*this)
    {
        initiate_resolve();
    }

    void async_write_binary(const char* data, size_t size, util::UniqueFunction<void()>&& handler) override
    {
        m_websocket.async_write_binary(data, size, std::move(handler));
    }

    // public for HTTPClient CRTP, but not on the WebSocket interface, so de-facto private
    void async_read(char*, std::size_t, ReadCompletionHandler) override;
    void async_read_until(char*, std::size_t, char, ReadCompletionHandler) override;
    void async_write(const char*, std::size_t, WriteCompletionHandler) override;

private:
    using milliseconds_type = std::int_fast64_t;

    util::Logger& websocket_get_logger() noexcept override
    {
        return m_legacy_config.logger;
    }
    std::mt19937_64& websocket_get_random() noexcept override
    {
        return m_legacy_config.random;
    }

    void websocket_handshake_completion_handler(const util::HTTPHeaders& headers) override
    {
        const std::string empty;
        auto it = headers.find("Sec-WebSocket-Protocol");
        m_observer.websocket_handshake_completion_handler(it == headers.end() ? empty : it->second);
    }
    void websocket_read_error_handler(std::error_code ec) override
    {
        logger().error("Reading failed: %1", ec.message()); // Throws
        m_observer.websocket_read_or_write_error_handler(ec);
    }
    void websocket_write_error_handler(std::error_code ec) override
    {
        logger().error("Writing failed: %1", ec.message()); // Throws
        m_observer.websocket_read_or_write_error_handler(ec);
    }
    void websocket_handshake_error_handler(std::error_code ec, const util::HTTPHeaders*,
                                           const std::string_view* body) override
    {
        m_observer.websocket_handshake_error_handler(ec, body);
    }
    void websocket_protocol_error_handler(std::error_code ec) override
    {
        m_observer.websocket_protocol_error_handler(ec);
    }
    bool websocket_close_message_received(std::error_code ec, StringData message) override
    {
        return m_observer.websocket_close_message_received(ec, message);
    }
    bool websocket_binary_message_received(const char* ptr, std::size_t size) override
    {
        return m_observer.websocket_binary_message_received(ptr, size);
    }

    void initiate_resolve();
    void handle_resolve(std::error_code, util::network::Endpoint::List);
    void initiate_tcp_connect(util::network::Endpoint::List, std::size_t);
    void handle_tcp_connect(std::error_code, util::network::Endpoint::List, std::size_t);
    void initiate_http_tunnel();
    void handle_http_tunnel(std::error_code);
    void initiate_websocket_or_ssl_handshake();
    void initiate_ssl_handshake();
    void handle_ssl_handshake(std::error_code);
    void initiate_websocket_handshake();
    void handle_connection_established();

    util::Logger& logger() const
    {
        return m_legacy_config.logger;
    }

    const SocketFactoryConfig& m_config;
    const DefaultSocketFactoryConfig& m_legacy_config;
    SocketObserver& m_observer;

    const Endpoint m_endpoint;
    util::Optional<util::network::Resolver> m_resolver;
    util::Optional<util::network::Socket> m_socket;
    util::Optional<util::network::ssl::Context> m_ssl_context;
    util::Optional<util::network::ssl::Stream> m_ssl_stream;
    util::network::ReadAheadBuffer m_read_ahead_buffer;
    util::websocket::Socket m_websocket;
    util::Optional<util::HTTPClient<LegacyWebsocketImpl>> m_proxy_client;
};

void LegacyWebsocketImpl::async_read(char* buffer, std::size_t size, ReadCompletionHandler handler)
{
    REALM_ASSERT(m_socket);
    if (m_ssl_stream) {
        m_ssl_stream->async_read(buffer, size, m_read_ahead_buffer, std::move(handler)); // Throws
    }
    else {
        m_socket->async_read(buffer, size, m_read_ahead_buffer, std::move(handler)); // Throws
    }
}

void LegacyWebsocketImpl::async_read_until(char* buffer, std::size_t size, char delim, ReadCompletionHandler handler)
{
    REALM_ASSERT(m_socket);
    if (m_ssl_stream) {
        m_ssl_stream->async_read_until(buffer, size, delim, m_read_ahead_buffer, std::move(handler)); // Throws
    }
    else {
        m_socket->async_read_until(buffer, size, delim, m_read_ahead_buffer, std::move(handler)); // Throws
    }
}

void LegacyWebsocketImpl::async_write(const char* data, std::size_t size, WriteCompletionHandler handler)
{
    REALM_ASSERT(m_socket);
    if (m_ssl_stream) {
        m_ssl_stream->async_write(data, size, std::move(handler)); // Throws
    }
    else {
        m_socket->async_write(data, size, std::move(handler)); // Throws
    }
}

void LegacyWebsocketImpl::initiate_resolve()
{
    const std::string& address = m_endpoint.proxy ? m_endpoint.proxy->address : m_endpoint.address;
    const port_type& port = m_endpoint.proxy ? m_endpoint.proxy->port : m_endpoint.port;

    if (m_endpoint.proxy) {
        // logger.detail("Using %1 proxy", proxy->type); // Throws
    }

    logger().detail("Resolving '%1:%2'", address, port); // Throws

    util::network::Resolver::Query query(address, util::to_string(port)); // Throws
    auto handler = [this](std::error_code ec, util::network::Endpoint::List endpoints) {
        // If the operation is aborted, the connection object may have been
        // destroyed.
        if (ec != util::error::operation_aborted)
            handle_resolve(ec, std::move(endpoints)); // Throws
    };
    m_resolver.emplace(m_legacy_config.service);               // Throws
    m_resolver->async_resolve(std::move(query), std::move(handler)); // Throws
}

void LegacyWebsocketImpl::handle_resolve(std::error_code ec, util::network::Endpoint::List endpoints)
{
    if (ec) {
        logger().error("Failed to resolve '%1:%2': %3", m_endpoint.address, m_endpoint.port, ec.message()); // Throws
        m_observer.websocket_connect_error_handler(ec);                                                     // Throws
        return;
    }

    initiate_tcp_connect(std::move(endpoints), 0); // Throws
}

void LegacyWebsocketImpl::initiate_tcp_connect(util::network::Endpoint::List endpoints, std::size_t i)
{
    REALM_ASSERT(i < endpoints.size());

    util::network::Endpoint ep = *(endpoints.begin() + i);
    std::size_t n = endpoints.size();
    m_socket.emplace(m_legacy_config.service); // Throws
    m_socket->async_connect(ep, [this, endpoints = std::move(endpoints), i](std::error_code ec) mutable {
        // If the operation is aborted, the connection object may have been
        // destroyed.
        if (ec != util::error::operation_aborted)
            handle_tcp_connect(ec, std::move(endpoints), i); // Throws
    });
    logger().detail("Connecting to endpoint '%1:%2' (%3/%4)", ep.address(), ep.port(), (i + 1), n); // Throws
}

void LegacyWebsocketImpl::handle_tcp_connect(std::error_code ec, util::network::Endpoint::List endpoints, std::size_t i)
{
    REALM_ASSERT(i < endpoints.size());
    const util::network::Endpoint& ep = *(endpoints.begin() + i);
    if (ec) {
        logger().error("Failed to connect to endpoint '%1:%2': %3", ep.address(), ep.port(),
                       ec.message()); // Throws
        std::size_t i_2 = i + 1;
        if (i_2 < endpoints.size()) {
            initiate_tcp_connect(std::move(endpoints), i_2); // Throws
            return;
        }
        // All endpoints failed
        logger().error("Failed to connect to '%1:%2': All endpoints failed", m_endpoint.address, m_endpoint.port);
        m_observer.websocket_connect_error_handler(ec); // Throws
        return;
    }

    REALM_ASSERT(m_socket);
    util::network::Endpoint ep_2 = m_socket->local_endpoint();
    logger().info("Connected to endpoint '%1:%2' (from '%3:%4')", ep.address(), ep.port(), ep_2.address(),
                  ep_2.port()); // Throws

    // TODO: Handle HTTPS proxies
    if (m_endpoint.proxy) {
        initiate_http_tunnel(); // Throws
        return;
    }

    initiate_websocket_or_ssl_handshake(); // Throws
}

void LegacyWebsocketImpl::initiate_websocket_or_ssl_handshake()
{
    if (m_endpoint.is_ssl) {
        initiate_ssl_handshake(); // Throws
    }
    else {
        initiate_websocket_handshake(); // Throws
    }
}

void LegacyWebsocketImpl::initiate_http_tunnel()
{
    HTTPRequest req;
    req.method = HTTPMethod::Connect;
    req.headers.emplace("Host", util::format("%1:%2", m_endpoint.address, m_endpoint.port));
    // TODO handle proxy authorization

    m_proxy_client.emplace(*this, logger());
    auto handler = [this](HTTPResponse response, std::error_code ec) {
        if (ec && ec != util::error::operation_aborted) {
            logger().error("Failed to establish HTTP tunnel: %1", ec.message());
            m_observer.websocket_connect_error_handler(ec); // Throws
            return;
        }

        if (response.status != HTTPStatus::Ok) {
            logger().error("Proxy server returned response '%1 %2'", response.status, response.reason); // Throws
            std::error_code ec2 =
                util::websocket::Error::bad_response_unexpected_status_code; // FIXME: is this the right error?
            m_observer.websocket_connect_error_handler(ec2);                 // Throws
            return;
        }

        initiate_websocket_or_ssl_handshake(); // Throws
    };

    m_proxy_client->async_request(req, std::move(handler)); // Throws
}

void LegacyWebsocketImpl::initiate_ssl_handshake()
{
    using namespace util::network::ssl;

    if (!m_ssl_context) {
        m_ssl_context.emplace(); // Throws
        if (m_endpoint.verify_servers_ssl_certificate) {
            if (m_endpoint.ssl_trust_certificate_path) {
                m_ssl_context->use_verify_file(*m_endpoint.ssl_trust_certificate_path); // Throws
            }
            else if (!m_endpoint.ssl_verify_callback) {
                m_ssl_context->use_default_verify(); // Throws
            }
        }
    }

    m_ssl_stream.emplace(*m_socket, *m_ssl_context, Stream::client); // Throws
    m_ssl_stream->set_logger(&logger());
    m_ssl_stream->set_host_name(m_endpoint.address); // Throws
    if (m_endpoint.verify_servers_ssl_certificate) {
        m_ssl_stream->set_verify_mode(VerifyMode::peer); // Throws
        m_ssl_stream->set_server_port(m_endpoint.port);
        if (!m_endpoint.ssl_trust_certificate_path) {
            if (m_endpoint.ssl_verify_callback) {
                m_ssl_stream->use_verify_callback(m_endpoint.ssl_verify_callback);
            }
            else {
                // The included certificates are used if neither the trust
                // certificate nor the callback function is set.
#if REALM_INCLUDE_CERTS
                m_ssl_stream->use_included_certificates(); // Throws
#endif
            }
        }
    }

    auto handler = [this](std::error_code ec) {
        // If the operation is aborted, the connection object may have been
        // destroyed.
        if (ec != util::error::operation_aborted)
            handle_ssl_handshake(ec); // Throws
    };
    m_ssl_stream->async_handshake(std::move(handler)); // Throws

    // FIXME: We also need to perform the SSL shutdown operation somewhere
}

void LegacyWebsocketImpl::handle_ssl_handshake(std::error_code ec)
{
    if (ec) {
        REALM_ASSERT(ec != util::error::operation_aborted);
        m_observer.websocket_ssl_handshake_error_handler(ec); // Throws
        return;
    }

    initiate_websocket_handshake(); // Throws
}

void LegacyWebsocketImpl::initiate_websocket_handshake()
{
    auto headers = util::HTTPHeaders(m_endpoint.headers.begin(), m_endpoint.headers.end());
    headers["User-Agent"] = m_config.user_agent;

    // Compute the value of the "Host" header.
    const std::uint_fast16_t default_port = (m_endpoint.is_ssl ? 443 : 80);
    auto host = m_endpoint.port == default_port ? m_endpoint.address
                                                : util::format("%1:%2", m_endpoint.address, m_endpoint.port);

    m_websocket.initiate_client_handshake(m_endpoint.path, std::move(host), m_endpoint.protocols,
                                          std::move(headers)); // Throws
}
} // namespace

WebSocket::~WebSocket() = default;

std::unique_ptr<WebSocket> DefaultSocketFactory::connect(SocketObserver* observer, Endpoint&& endpoint)
{
    return std::make_unique<LegacyWebsocketImpl>(m_config, m_legacy_config, *observer, std::move(endpoint));
}

} // namespace realm::util::websocket