const getTokenByReq = (req) => {
  const authorization = req.headers.authorization || "";
  const token = authorization.split(" ")[1];
  return token;
};

module.exports = {
  getTokenByReq,
};
