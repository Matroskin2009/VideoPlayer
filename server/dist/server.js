"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var hono_1 = require("hono");
var node_server_1 = require("@hono/node-server");
var app = new hono_1.Hono();
// Пример API-эндпоинта для взаимодействия с frontend
app.get('/api/hello', function (c) {
    return c.json({ message: 'Hello from backend via Hono!' });
});
// Запуск сервера на порту 3001
(0, node_server_1.serve)({ fetch: app.fetch, port: 3001 }, function (info) {
    console.log("Listening on http://localhost:".concat(info.port));
});
