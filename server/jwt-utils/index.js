const jwt = require("jsonwebtoken");
var CryptoJS = require("crypto-js");
// 私有密匙
const privateKey = "66cc5720-f374-4a6f-b6ab-8b9efe18fd65";

/**
 * 创建token
 * @param {*} data 存储的信息
 * @param {number} expiresIn 过期时间 s秒
 * @returns
 */
const createToken = (data = {}, expiresIn) => {
  let token = "";
  if (typeof expiresIn === "number") {
    // 生成token data存储的信息、 privateKey私有key  参数3 加密方式 默认HMAC HS256  expiresIn 过期时间s
    token = jwt.sign(data, privateKey, { algorithm: "HS256", expiresIn });
  } else {
    // 生成token data存储的信息、 privateKey私有key  参数3 加密方式 默认HMAC HS256
    token = jwt.sign(data, privateKey, { algorithm: "HS256" });
  }

  return token;
};

/**
 * 校验token
 * @param {*} token
 * @returns
 */
const verifyToken = (token) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, privateKey, { algorithm: "HS256" }, (err, decoded) => {
      if (err) {
        switch (err.name) {
          case "TokenExpiredError":
            reject("token已失效");
            break;
          case "JsonWebTokenError":
            reject("token校验失败");
          case "NotBeforeError":
            reject("token还未生效");
            break;
          default:
            reject("token校验失败");
        }
      } else {
        resolve(decoded);
      }
    });
  });
};

const createMyToken = (data) => {
  // 创建header
  const headerBuffer = Buffer.from(
    JSON.stringify({
      alg: "HS256",
      typ: "JWT",
    })
  );
  const header = headerBuffer.toString("base64");

  // 创建payload
  const payloadBuffer = Buffer.from(
    JSON.stringify({ username: "zs", age: 18, iat: "1678952863" })
  );
  const payload = payloadBuffer.toString("base64");

  const singnature = CryptoJS.HmacSHA256(
    `${header}.${payload}`,
    privateKey
  ).toString(CryptoJS.enc.Base64url);
  // console.log("singnature", `${header}.${payload}`, singnature);
  const token = `${header}.${payload}.${singnature}`;
  console.log(token);

  // 创建payload
};

module.exports = {
  createToken,
  verifyToken,
};
