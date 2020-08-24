const jwt = require("jsonwebtoken");

module.exports = (context) => {
  if (context.req && context.req.headers.authorization) {
    const token = context.req.headers.authorization.split("Bearer ")[1];
    jwt.verify(token, "secretkey", (err, decodedToken) => {
      context.user = decodedToken;
    });
  }
  return context;
};
