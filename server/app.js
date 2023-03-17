const express = require("express");
const exStatic = require("express-static");
const { createToken, verifyToken } = require("./jwt-utils");
const { getTokenByReq } = require("./utils");
const app = express();
const port = 3000;

//设置允许跨域
app.use(function (req, res, next) {
  //指定允许其他域名访问 *所有
  res.setHeader("Access-Control-Allow-Origin", "*");
  //允许客户端请求头中带有的
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Content-Length, Authorization, Accept,X-Requested-With"
  );
  //允许请求的类型
  res.setHeader("Access-Control-Allow-Methods", "PUT,POST,GET,DELETE,OPTIONS");
  res.setHeader("X-Powered-By", " 3.2.1");
  //让options请求快速返回
  if (req.method == "OPTIONS") res.send(200);
  else next();
});

app.get("*", async (req, res, next) => {
  // 白名单不进入校验token
  if (req.path.match(/(\.html$)|(\/login)|(\/refreshToken)/)) {
    return next();
  }

  try {
    const token = getTokenByReq(req);
    const decoded = await verifyToken(token);
    // 是刷新token
    if (decoded.refresh) {
      return res.status(402).json({
        code: 402,
        message: "refresh_token不能作为access_token使用",
      });
    } else {
      req.__decoded__ = decoded;
      // 是正常token放行
      return next();
    }
  } catch (error) {
    // 校验失败直接返回
    return res.status(401).json({
      code: 401,
      message: error,
    });
  }
  next();
});

app.get("/login", (req, res, next) => {
  // access_token
  const access_token = createToken(
    { id: 1, username: req.params.username, age: "18" },
    5
  );
  // 刷新token refresh_token
  const refresh_token = createToken({ id: 1, refresh: true }, 1 * 60 * 60);
  console.log(getTokenByReq(req));
  res.json({
    code: 200,
    access_token,
    refresh_token,
  });
  next();
});

app.get("/refreshToken", async (req, res, next) => {
  try {
    const refreshToken = req.query.refresh_token;
    const decoded = await verifyToken(refreshToken);
    if (decoded.refresh) {
      res.json({
        code: 200,
        access_token: createToken(
          {
            id: decoded.id,
            username: "zs",
          },
          5
        ),
      });
    } else {
      res.json({
        code: 404,
        message: "access_token不能作为refresh_token",
      });
    }
  } catch (error) {
    res.json({
      code: 404,
      message: "refresh_token已经失效",
    });
  }
});

app.get("/verify", async (req, res, next) => {
  try {
    const token = req.query.token;
    const decoded = await verifyToken(token);

    res.json({
      code: 200,
      decoded,
    });
  } catch (error) {
    res.json({
      code: 401,
      error,
    });
  }

  next();
});

app.get("/getList", async (req, res, next) => {
  res.json({
    list: [Date.now()],
    __decoded__: req.__decoded__,
  });

  next();
});
app.use(exStatic("./views"));

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
