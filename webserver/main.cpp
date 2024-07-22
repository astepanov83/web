#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/config.hpp>
#include <boost/make_unique.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

// Function to convert binary data to hex + ASCII
std::string hex_dump(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    const int bytes_per_line = 16;
    for (size_t i = 0; i < data.size(); ++i) {
        if (i % bytes_per_line == 0) {
            oss << std::setw(4) << std::setfill('0') << std::hex << i << " ";
        }
        oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]) << " ";
        if ((i + 1) % bytes_per_line == 0) {
            oss << " ";
            for (size_t j = i + 1 - bytes_per_line; j <= i; ++j) {
                if (std::isprint(data[j])) {
                    oss << static_cast<char>(data[j]);
                } else {
                    oss << '.';
                }
            }
            oss << '\n';
        }
    }
    if (data.size() % bytes_per_line != 0) {
        for (size_t i = data.size() % bytes_per_line; i < bytes_per_line; ++i) {
            oss << "   ";
        }
        oss << " ";
        for (size_t i = data.size() - data.size() % bytes_per_line; i < data.size(); ++i) {
            if (std::isprint(data[i])) {
                oss << static_cast<char>(data[i]);
            } else {
                oss << '.';
            }
        }
        oss << '\n';
    }
    return oss.str();
}

// Return a reasonable mime type based on the extension of a file.
beast::string_view mime_type(beast::string_view path) {
    using beast::iequals;
    auto const ext = [&path] {
        auto const pos = path.rfind(".");
        if (pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();
    if (iequals(ext, ".htm"))  return "text/html";
    if (iequals(ext, ".html")) return "text/html";
    return "application/text";
}

// Report a failure
void fail(beast::error_code ec, char const* what) {
    std::cerr << what << ": " << ec.message() << "\n";
}

// This function produces an HTTP response for the given request.
// The type of the response object depends on the contents of the request,
// so the interface requires the caller to pass a generic lambda for
// receiving the response.
template<class Body, class Allocator, class Send>
void handle_request(beast::string_view doc_root, http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send) {
    // Log the request data
    std::cout << "Received request: " << req << std::endl;

    // Respond to GET request
    if (req.method() == http::verb::get) {
        auto const response_body = std::make_shared<std::string>("Hello, World!");
        auto const size = response_body->size();

        http::response<http::string_body> res{ http::status::ok, req.version() };
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, mime_type(".html"));
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        res.body() = *response_body;

        // Log the response data
        std::cout << "Sending response: " << res << std::endl;

        return send(std::move(res));
    }

    // Otherwise return a "method not allowed" response
    http::response<http::string_body> res{ http::status::method_not_allowed, req.version() };
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = "Method not allowed";
    res.prepare_payload();

    // Log the response data
    std::cout << "Sending response: " << res << std::endl;

    return send(std::move(res));
}

// Handles an HTTP server connection
class session : public std::enable_shared_from_this<session> {
    struct send_lambda {
        session& self_;

        explicit send_lambda(session& self) : self_(self) {}

        template<bool isRequest, class Body, class Fields>
        void operator()(http::message<isRequest, Body, Fields>&& msg) const {
            auto sp = std::make_shared<http::message<isRequest, Body, Fields>>(std::move(msg));

            self_.res_ = sp;

            http::async_write(self_.stream_, *sp, beast::bind_front_handler(&session::on_write, self_.shared_from_this(), sp->need_eof()));
        }
    };

    beast::ssl_stream<beast::tcp_stream> stream_;
    beast::flat_buffer buffer_;
    std::shared_ptr<std::string const> doc_root_;
    http::request<http::string_body> req_;
    std::shared_ptr<void> res_;
    send_lambda lambda_;
    std::ofstream log_file_;
    std::vector<uint8_t> data_buffer_;

public:
    session(tcp::socket&& socket, ssl::context& ctx, std::shared_ptr<std::string const> const& doc_root)
        : stream_(std::move(socket), ctx), doc_root_(doc_root), lambda_(*this) {
        auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();
        std::string log_filename = "session_" + std::to_string(timestamp) + ".log";
        log_file_.open(log_filename, std::ios::out | std::ios::binary);
    }

    ~session() {
        if (log_file_.is_open()) {
            log_file_.close();
        }
    }

    void run() {
        net::dispatch(stream_.get_executor(), beast::bind_front_handler(&session::on_run, shared_from_this()));
    }

    void on_run() {
        stream_.async_handshake(ssl::stream_base::server, beast::bind_front_handler(&session::on_handshake, shared_from_this()));
    }

    void on_handshake(beast::error_code ec) {
        if (ec)
            return fail(ec, "handshake");

        do_read();
    }

    void do_read() {
        req_ = {};
        buffer_.consume(buffer_.size());
        http::async_read(stream_, buffer_, req_, beast::bind_front_handler(&session::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);

        if (ec == http::error::end_of_stream)
            return do_close();

        if (ec)
            return fail(ec, "read");

        data_buffer_.assign((char*)buffer_.data().data(), (char*)buffer_.data().data() + buffer_.size());
        log_file_ << hex_dump(data_buffer_) << std::endl;

        handle_request(*doc_root_, std::move(req_), lambda_);
    }

    void on_write(bool close, beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "write");

        if (close) {
            return do_close();
        }

        res_ = nullptr;

        do_read();
    }

    void do_close() {
        beast::error_code ec;
        stream_.shutdown(ec);
    }
};

class listener : public std::enable_shared_from_this<listener> {
    net::io_context& ioc_;
    ssl::context& ctx_;
    tcp::acceptor acceptor_;
    std::shared_ptr<std::string const> doc_root_;

public:
    listener(net::io_context& ioc, ssl::context& ctx, tcp::endpoint endpoint, std::shared_ptr<std::string const> const& doc_root)
        : ioc_(ioc), ctx_(ctx), acceptor_(net::make_strand(ioc)), doc_root_(doc_root) {
        beast::error_code ec;

        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            fail(ec, "open");
            return;
        }

        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            fail(ec, "set_option");
            return;
        }

        acceptor_.bind(endpoint, ec);
        if (ec) {
            fail(ec, "bind");
            return;
        }

        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            fail(ec, "listen");
            return;
        }
    }

    void run() {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(net::make_strand(ioc_), beast::bind_front_handler(&listener::on_accept, shared_from_this()));
    }

    void on_accept(beast::error_code ec, tcp::socket socket) {
        if (ec) {
            fail(ec, "accept");
        } else {
            std::make_shared<session>(std::move(socket), ctx_, doc_root_)->run();
        }

        do_accept();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <address> <port> <doc_root> <cert_file> <key_file>\n";
        return EXIT_FAILURE;
    }
    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const doc_root = std::make_shared<std::string>(argv[3]);
    auto const cert_file = argv[4];
    auto const key_file = argv[5];

    net::io_context ioc{ 1 };
    ssl::context ctx{ ssl::context::tlsv12 };

    ctx.use_certificate_chain_file(cert_file);
    ctx.use_private_key_file(key_file, ssl::context::pem);

    std::make_shared<listener>(ioc, ctx, tcp::endpoint{ address, port }, doc_root)->run();

    ioc.run();

    return EXIT_SUCCESS;
}
