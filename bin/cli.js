#!/usr/bin/env node

const server = require("../src/server");
const args = process.argv.slice(2);

let port = 3782;
const portArg = args.find((a) => a.startsWith("--port="));
if (portArg) port = parseInt(portArg.split("=")[1]);

server.start(port);
