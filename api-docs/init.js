// Swagger UI for Runtime's own API. Nothing is fetched from outside this server.
window.SwaggerUIBundle({
  url: "/api/openapi.json",
  dom_id: "#swagger",
  deepLinking: true,
  // The default validator badge calls validator.swagger.io; keep every request on this server.
  validatorUrl: null,
  defaultModelsExpandDepth: 1,
});
