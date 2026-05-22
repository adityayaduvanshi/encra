// Copyright 2026 Encra (encra.dev). Licensed under the Business Source License 1.1.
// See LICENSE in this package for terms. Free for non-commercial/non-production use.
// Commercial hosted-service use requires a license from Encra (encra.dev).
import 'dotenv/config'
import http from 'http'
import { createApp } from './app.js'
import { attachWebSocketRelay } from './ws/relay.js'

const PORT = parseInt(process.env['PORT'] ?? '3000', 10)

const app = createApp()
const server = http.createServer(app)
attachWebSocketRelay(server)

server.listen(PORT, () => {
  console.log(`e2e-chat-crypto server listening on port ${PORT}`)
})
