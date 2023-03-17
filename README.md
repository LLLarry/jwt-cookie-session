# 前端授权方案

## 什么是认证（Authentication）

- 通俗地讲就是**验证当前用户的身份**，证明“你是你自己”（比如：你每天上下班打卡，都需要通过指纹打卡，当你的指纹和系统里录入的指纹相匹配时，就打卡成功）
- 互联网中的认证：
  - 用户名密码登录
  - 邮箱发送登录链接
  - 手机号接收验证码
  - 只要你能收到邮箱/验证码，就默认你是账号的主人



## 什么是授权（Authorization）

- 用户授予第三方应用访问该用户某些资源的权限
  - 你在安装手机应用的时候，APP 会询问是否允许授予权限（访问相册、地理位置等权限）
  - 你在访问微信小程序时，当登录时，小程序会询问是否允许授予权限（获取昵称、头像、地区、性别等个人信息）
- 实现授权的方式有：cookie、session、token、OAuth



## 什么是凭证（Credentials）

- 实现认证和授权的前提

  是需要一种

  媒介（证书）

   来标记访问者的身份

  - 在战国时期，商鞅变法，发明了照身帖。照身帖由官府发放，是一块打磨光滑细密的竹板，上面刻有持有人的头像和籍贯信息。国人必须持有，如若没有就被认为是黑户，或者间谍之类的。
  - 在现实生活中，每个人都会有一张专属的[居民身份证](https://link.juejin.cn?target=https%3A%2F%2Fbaike.baidu.com%2Fitem%2F%E5%B1%85%E6%B0%91%E8%BA%AB%E4%BB%BD%E8%AF%81%2F2080960)，是用于证明持有人身份的一种法定[证件](https://link.juejin.cn?target=https%3A%2F%2Fbaike.baidu.com%2Fitem%2F%E8%AF%81%E4%BB%B6%2F5804999)。通过身份证，我们可以办理手机卡/银行卡/个人贷款/交通出行等等，这就是**认证的凭证。**
  - 在互联网应用中，一般网站（如掘金）会有两种模式，游客模式和登录模式。游客模式下，可以正常浏览网站上面的文章，一旦想要点赞/收藏/分享文章，就需要登录或者注册账号。当用户登录成功后，服务器会给该用户使用的浏览器颁发一个令牌（token），这个令牌用来表明你的身份，每次浏览器发送请求时会带上这个令牌，就可以使用游客模式下无法使用的功能。



## 什么是 Cookie

- **HTTP 是无状态的协议（对于事务处理没有记忆能力，每次客户端和服务端会话完成时，服务端不会保存任何会话信息**）：每个请求都是完全独立的，服务端无法确认当前访问者的身份信息，无法分辨上一次的请求发送者和这一次的发送者是不是同一个人。所以服务器与浏览器为了进行会话跟踪（知道是谁在访问我），就必须主动的去维护一个状态，这个状态用于告知服务端前后两个请求是否来自同一浏览器。而这个状态需要通过 cookie 或者 session 去实现。
- **cookie 存储在客户端：** cookie 是服务器发送到用户浏览器并保存在本地的一小块数据，它会在浏览器下次向同一服务器再发起请求时被携带并发送到服务器上。
- **cookie 是不可跨域的：** 每个 cookie 都会绑定单一的域名，无法在别的域名下获取使用，**一级域名和二级域名之间是允许共享使用的**（**靠的是 domain）**。

**cookie 重要的属性**

| 属性           | 说明                                                         |
| -------------- | ------------------------------------------------------------ |
| **name=value** | 键值对，设置 Cookie 的名称及相对应的值，都必须是**字符串类型** - 如果值为 Unicode 字符，需要为字符编码。 - 如果值为二进制数据，则需要使用 BASE64 编码。 |
| **domain**     | 指定 cookie 所属域名，默认是当前域名                         |
| **path**       | **指定 cookie 在哪个路径（路由）下生效，默认是 '/'**。 如果设置为 `/abc`，则只有 `/abc` 下的路由可以访问到该 cookie，如：`/abc/read`。 |
| **maxAge**     | cookie 失效的时间，单位秒。如果为整数，则该 cookie 在 maxAge 秒后失效。如果为负数，该 cookie 为临时 cookie ，关闭浏览器即失效，浏览器也不会以任何形式保存该 cookie 。如果为 0，表示删除该 cookie 。默认为 -1。 - **比 expires 好用**。 |
| **expires**    | 过期时间，在设置的某个时间点后该 cookie 就会失效。 一般浏览器的 cookie 都是默认储存的，当关闭浏览器结束这个会话的时候，这个 cookie 也就会被删除 |
| **secure**     | 该 cookie 是否仅被使用安全协议传输。安全协议有 HTTPS，SSL等，在网络上传输数据之前先将数据加密。默认为false。 当 secure 值为 true 时，cookie 在 HTTP 中是无效，在 HTTPS 中才有效。 |
| **httpOnly**   | **如果给某个 cookie 设置了 httpOnly 属性，则无法通过 JS 脚本 读取到该 cookie 的信息，但还是能通过 Application 中手动修改 cookie，所以只是在一定程度上可以防止 XSS 攻击，不是绝对的安全** |
|                |                                                              |



## 什么是 Session

- **session 是另一种记录服务器和客户端会话状态的机制**
- **session 是基于 cookie 实现的，session 存储在服务器端，sessionId 会被存储到客户端的cookie 中**



![session.png](images/16f523a04d0b3cf5tplv-t2oaga2asx-zoom-in-crop-mark3024000.awebp)



- session 认证流程：
  - 用户第一次请求服务器的时候，服务器根据用户提交的相关信息，创建对应的 Session
  - 请求返回时将此 Session 的唯一标识信息 SessionID 返回给浏览器
  - 浏览器接收到服务器返回的 SessionID 信息后，会将此信息存入到 Cookie 中，同时 Cookie 记录此 SessionID 属于哪个域名
  - 当用户第二次访问服务器的时候，请求会自动判断此域名下是否存在 Cookie 信息，如果存在自动将 Cookie 信息也发送给服务端，服务端会从 Cookie 中获取 SessionID，再根据 SessionID 查找对应的 Session 信息，如果没有找到说明用户没有登录或者登录失效，如果找到 Session 证明用户已经登录可执行后面操作。

根据以上流程可知，**SessionID 是连接 Cookie 和 Session 的一道桥梁**，大部分系统也是根据此原理来验证用户登录状态。



## Cookie 和 Session 的区别

- **安全性：** Session 比 Cookie 安全，Session 是存储在服务器端的，Cookie 是存储在客户端的。
- **存取值的类型不同**：Cookie 只支持存字符串数据，想要设置其他类型的数据，需要将其转换成字符串，Session 可以存任意数据类型。
- **有效期不同：** Cookie 可设置为长时间保持，比如我们经常使用的默认登录功能，Session 一般失效时间较短，客户端关闭（默认情况下）或者 Session 超时都会失效。
- **存储大小不同：** 单个 Cookie 保存的数据不能超过 4K，Session 可存储数据远高于 Cookie，但是当访问量过多，会占用过多的服务器资源。



## 什么是 Token（令牌）



### Acesss Token

- **访问资源接口（API）时所需要的资源凭证**
- **简单 token 的组成：** uid(用户唯一的身份标识)、time(当前时间的时间戳)、sign（签名，token 的前几位以哈希算法压缩成的一定长度的十六进制字符串）
- 特点：
  - **服务端无状态化、可扩展性好**
  - **支持移动端设备**
  - 安全
  - 支持跨程序调用
- **token 的身份验证流程：**



![img](images/16f523a04d9c745ftplv-t2oaga2asx-zoom-in-crop-mark3024000.awebp)



1. 客户端使用用户名跟密码请求登录
2. 服务端收到请求，去验证用户名与密码
3. 验证成功后，服务端会签发一个 token 并把这个 token 发送给客户端
4. 客户端收到 token 以后，会把它存储起来，比如放在 cookie 里或者 localStorage 里
5. 客户端每次向服务端请求资源的时候需要带着服务端签发的 token
6. 服务端收到请求，然后去验证客户端请求里面带着的 token ，如果验证成功，就向客户端返回请求的数据

- **每一次请求都需要携带 token，需要把 token 放到 HTTP 的 Header 里**
- **基于 token 的用户认证是一种服务端无状态的认证方式，服务端不用存放 token 数据。用解析 token 的计算时间换取 session 的存储空间，从而减轻服务器的压力，减少频繁的查询数据库**
- **token 完全由应用管理，所以它可以避开同源策略**



### Refresh Token

- 另外一种 token——refresh token
- refresh token 是专用于刷新 access token 的 token。如果没有 refresh token，也可以刷新 access token，但每次刷新都要用户输入登录用户名与密码，会很麻烦。有了 refresh token，可以减少这个麻烦，客户端直接用 refresh token 去更新 access token，无需用户进行额外的操作。



![img](images/16f523a04d1c887btplv-t2oaga2asx-zoom-in-crop-mark3024000.awebp)



- Access Token 的有效期比较短，当 Acesss Token 由于过期而失效时，使用 Refresh Token 就可以获取到新的 Token，如果 Refresh Token 也失效了，用户就只能重新登录了。
- Refresh Token 及过期时间是存储在服务器的数据库中，只有在申请新的 Acesss Token 时才会验证，不会对业务接口响应时间造成影响，也不需要向 Session 一样一直保持在内存中以应对大量的请求。



## Token 和 Session 的区别

- Session 是一种**记录服务器和客户端会话状态的机制，使服务端有状态化，可以记录会话信息**。而 Token 是**令牌**，**访问资源接口（API）时所需要的资源凭证**。Token **使服务端无状态化，不会存储会话信息。**
- Session 和 Token 并不矛盾，作为身份认证 Token 安全性比 Session 好，因为每一个请求都有签名还能防止监听以及重放攻击，而 Session 就必须依赖链路层来保障通讯安全了。**如果你需要实现有状态的会话，仍然可以增加 Session 来在服务器端保存一些状态。**
- 所谓 Session 认证只是简单的把 User 信息存储到 Session 里，因为 SessionID 的不可预测性，暂且认为是安全的。而 Token ，如果指的是 OAuth Token 或类似的机制的话，提供的是 认证 和 授权 ，认证是针对用户，授权是针对 App 。其目的是让某 App 有权利访问某用户的信息。这里的 Token 是唯一的。不可以转移到其它 App上，也不可以转到其它用户上。Session 只提供一种简单的认证，即只要有此 SessionID ，即认为有此 User 的全部权利。是需要严格保密的，这个数据应该只保存在站方，不应该共享给其它网站或者第三方 App。所以简单来说：**如果你的用户数据可能需要和第三方共享，或者允许第三方调用 API 接口，用 Token 。如果永远只是自己的网站，自己的 App，用什么就无所谓了。**



## 什么是 JWT

- JSON Web Token（简称 JWT）是目前最流行的**跨域认证**解决方案。
- 是一种**认证授权机制**。
- JWT 是为了在网络应用环境间**传递声明**而执行的一种基于 JSON 的开放标准（[RFC 7519](https://link.juejin.cn?target=https%3A%2F%2Ftools.ietf.org%2Fhtml%2Frfc7519)）。JWT 的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源。比如用在用户登录上。
- 可以使用 HMAC 算法或者是 RSA 的公/私秘钥对 JWT 进行签名。因为数字签名的存在，这些传递的信息是可信的。
- **阮一峰老师的 [JSON Web Token 入门教程](https://link.juejin.cn?target=http%3A%2F%2Fwww.ruanyifeng.com%2Fblog%2F2018%2F07%2Fjson_web_token-tutorial.html) 讲的非常通俗易懂，这里就不再班门弄斧了**



### 生成 JWT

[jwt.io/](https://link.juejin.cn?target=https%3A%2F%2Fjwt.io%2F)
[www.jsonwebtoken.io/](https://link.juejin.cn?target=https%3A%2F%2Fwww.jsonwebtoken.io%2F)

### JWT 的原理



![img](images/16f523a04e881087tplv-t2oaga2asx-zoom-in-crop-mark3024000.awebp)



- JWT 认证流程：
  - 用户输入用户名/密码登录，服务端认证成功后，会返回给客户端一个 JWT
  - 客户端将 token 保存到本地（通常使用 localstorage，也可以使用 cookie）
  - 当用户希望访问一个受保护的路由或者资源的时候，需要请求头的 Authorization 字段中使用Bearer 模式添加 JWT，其内容看起来是下面这样

```xml
Authorization: Bearer <token>复制代码
```

- 服务端的保护路由将会检查请求头 Authorization 中的 JWT 信息，如果合法，则允许用户的行为
- 因为 JWT 是自包含的（内部包含了一些会话信息），因此减少了需要查询数据库的需要
- 因为 JWT 并不使用 Cookie 的，所以你可以使用任何域名提供你的 API 服务而不需要担心跨域资源共享问题（CORS）
- 因为用户的状态不再存储在服务端的内存中，所以这是一种无状态的认证机制



### JWT 的使用方式

- 客户端收到服务器返回的 JWT，可以储存在 Cookie 里面，也可以储存在 localStorage。



#### 方式一

- 当用户希望访问一个受保护的路由或者资源的时候，可以把它放在 Cookie 里面自动发送，但是这样不能跨域，所以更好的做法是放在 HTTP 请求头信息的 Authorization 字段里，使用 Bearer 模式添加 JWT。

  ```dts
  GET /calendar/v1/events
  Host: api.example.com
  Authorization: Bearer <token>复制代码
  ```

  - 用户的状态不会存储在服务端的内存中，这是一种 **无状态的认证机制**
  - 服务端的保护路由将会检查请求头 Authorization 中的 JWT 信息，如果合法，则允许用户的行为。
  - 由于 JWT 是自包含的，因此减少了需要查询数据库的需要
  - JWT 的这些特性使得我们可以完全依赖其无状态的特性提供数据 API 服务，甚至是创建一个下载流服务。
  - 因为 JWT 并不使用 Cookie ，所以你可以使用任何域名提供你的 API 服务而**不需要担心跨域资源共享问题**（CORS）



#### 方式二

- 跨域的时候，可以把 JWT 放在 POST 请求的数据体里。



#### 方式三

- 通过 URL 传输

```awk
http://www.example.com/user?token=xxx复制代码
```



### 项目中使用 JWT

[**项目地址**](https://link.juejin.cn?target=https%3A%2F%2Fgithub.com%2Fyjdjiayou%2Fjwt-demo)

## Token 和 JWT 的区别  

**相同：**

- 都是访问资源的令牌
- 都可以记录用户的信息
- 都是使服务端无状态化
- 都是只有验证成功后，客户端才能访问服务端上受保护的资源

**区别：**

- Token：服务端验证客户端发送过来的 Token 时，还需要查询数据库获取用户信息，然后验证 Token 是否有效。
- JWT： 将 Token 和 Payload 加密后存储于客户端，服务端只需要使用密钥解密进行校验（校验也是 JWT 自己实现的）即可，不需要查询或者减少查询数据库，因为 JWT 自包含了用户信息和加密的数据。



## 常见的前后端鉴权方式 

1. Session-Cookie
2. Token 验证（包括 JWT，SSO）
3. OAuth2.0（开放授权）



## 常见的加密算法



![image.png](images/16f523a04f17f2fctplv-t2oaga2asx-zoom-in-crop-mark3024000.awebp)



- 哈希算法(Hash Algorithm)又称散列算法、散列函数、哈希函数，是一种从任何一种数据中创建小的数字“指纹”的方法。哈希算法将数据重新打乱混合，重新创建一个哈希值。
- 哈希算法主要用来保障数据真实性(即完整性)，即发信人将原始消息和哈希值一起发送，收信人通过相同的哈希函数来校验原始数据是否真实。
- 哈希算法通常有以下几个特点：
  - 正像快速：原始数据可以快速计算出哈希值
  - 逆向困难：通过哈希值基本不可能推导出原始数据
  - 输入敏感：原始数据只要有一点变动，得到的哈希值差别很大
  - 冲突避免：很难找到不同的原始数据得到相同的哈希值，宇宙中原子数大约在 10 的 60 次方到 80 次方之间，所以 2 的 256 次方有足够的空间容纳所有的可能，算法好的情况下冲突碰撞的概率很低：
    - 2 的 128 次方为 340282366920938463463374607431768211456，也就是 10 的 39 次方级别
    - 2 的 160 次方为 1.4615016373309029182036848327163e+48，也就是 10 的 48 次方级别
    - 2 的 256 次方为 1.1579208923731619542357098500869 × 10 的 77 次方，也就是 10 的 77 次方

**注意：**

1. 以上不能保证数据被恶意篡改，原始数据和哈希值都可能被恶意篡改，要保证不被篡改，可以使用RSA 公钥私钥方案，再配合哈希值。
2. 哈希算法主要用来防止计算机传输过程中的错误，早期计算机通过前 7 位数据第 8 位奇偶校验码来保障（12.5% 的浪费效率低），对于一段数据或文件，通过哈希算法生成 128bit 或者 256bit 的哈希值，如果校验有问题就要求重传。



## 常见问题



### 使用 cookie 时需要考虑的问题

- 因为存储在客户端，容易被客户端篡改，使用前需要验证合法性
- 不要存储敏感数据，比如用户密码，账户余额
- 使用 httpOnly 在一定程度上提高安全性
- 尽量减少 cookie 的体积，能存储的数据量不能超过 4kb
- 设置正确的 domain 和 path，减少数据传输
- **cookie 无法跨域**
- 一个浏览器针对一个网站最多存 20 个Cookie，浏览器一般只允许存放 300 个Cookie
- **移动端对 cookie 的支持不是很好，而 session 需要基于 cookie 实现，所以移动端常用的是 token**



### 使用 session 时需要考虑的问题

- 将 session 存储在服务器里面，当用户同时在线量比较多时，这些 session 会占据较多的内存，需要在服务端定期的去清理过期的 session
- 当网站采用**集群部署**的时候，会遇到多台 web 服务器之间如何做 session 共享的问题。因为 session 是由单个服务器创建的，但是处理用户请求的服务器不一定是那个创建 session 的服务器，那么该服务器就无法拿到之前已经放入到 session 中的登录凭证之类的信息了。
- 当多个应用要共享 session 时，除了以上问题，还会遇到跨域问题，因为不同的应用可能部署的主机不一样，需要在各个应用做好 cookie 跨域的处理。
- **sessionId 是存储在 cookie 中的，假如浏览器禁止 cookie 或不支持 cookie 怎么办？** 一般会把 sessionId 跟在 url 参数后面即重写 url，所以 session 不一定非得需要靠 cookie 实现
- **移动端对 cookie 的支持不是很好，而 session 需要基于 cookie 实现，所以移动端常用的是 token**



### 使用 token 时需要考虑的问题

- 如果你认为用数据库来存储 token 会导致查询时间太长，可以选择放在内存当中。比如 redis 很适合你对 token 查询的需求。
- **token 完全由应用管理，所以它可以避开同源策略**
- **token 可以避免 CSRF 攻击(因为不需要 cookie 了)**
- **移动端对 cookie 的支持不是很好，而 session 需要基于 cookie 实现，所以移动端常用的是 token**



### 使用 JWT 时需要考虑的问题

- 因为 JWT 并不依赖 Cookie 的，所以你可以使用任何域名提供你的 API 服务而不需要担心跨域资源共享问题（CORS）
- JWT 默认是不加密，但也是可以加密的。生成原始 Token 以后，可以用密钥再加密一次。
- JWT 不加密的情况下，不能将秘密数据写入 JWT。
- JWT 不仅可以用于认证，也可以用于交换信息。有效使用 JWT，可以降低服务器查询数据库的次数。
- JWT 最大的优势是服务器不再需要存储 Session，使得服务器认证鉴权业务可以方便扩展。但这也是 JWT 最大的缺点：由于服务器不需要存储 Session 状态，因此使用过程中无法废弃某个 Token 或者更改 Token 的权限。也就是说一旦 JWT 签发了，到期之前就会始终有效，除非服务器部署额外的逻辑。
- JWT 本身包含了认证信息，一旦泄露，任何人都可以获得该令牌的所有权限。为了减少盗用，JWT的有效期应该设置得比较短。对于一些比较重要的权限，使用时应该再次对用户进行认证。
- JWT 适合一次性的命令认证，颁发一个有效期极短的 JWT，即使暴露了危险也很小，由于每次操作都会生成新的 JWT，因此也没必要保存 JWT，真正实现无状态。
- 为了减少盗用，JWT 不应该使用 HTTP 协议明码传输，要使用 HTTPS 协议传输。



### 使用加密算法时需要考虑的问题

- 绝不要以**明文存储**密码
- **永远使用 哈希算法 来处理密码，绝不要使用 Base64 或其他编码方式来存储密码，这和以明文存储密码是一样的，使用哈希，而不要使用编码**。编码以及加密，都是双向的过程，而密码是保密的，应该只被它的所有者知道， 这个过程必须是单向的。哈希正是用于做这个的，从来没有解哈希这种说法， 但是编码就存在解码，加密就存在解密。
- 绝不要使用弱哈希或已被破解的哈希算法，像 MD5 或 SHA1 ，只使用强密码哈希算法。
- 绝不要以明文形式显示或发送密码，即使是对密码的所有者也应该这样。如果你需要 “忘记密码” 的功能，可以随机生成一个新的 **一次性的**（这点很重要）密码，然后把这个密码发送给用户。



### 分布式架构下 session 共享方案



#### 1. session 复制

- 任何一个服务器上的 session 发生改变（增删改），该节点会把这个 session 的所有内容序列化，然后广播给所有其它节点，不管其他服务器需不需要 session ，以此来保证 session 同步

**优点：** 可容错，各个服务器间 session 能够实时响应。 
 **缺点：** 会对网络负荷造成一定压力，如果 session 量大的话可能会造成网络堵塞，拖慢服务器性能。



#### 2. 粘性 session /IP 绑定策略

- **采用 Ngnix 中的 ip_hash 机制，将某个 ip的所有请求都定向到同一台服务器上，即将用户与服务器绑定。** 用户第一次请求时，负载均衡器将用户的请求转发到了 A 服务器上，如果负载均衡器设置了粘性 session 的话，那么用户以后的每次请求都会转发到 A 服务器上，相当于把用户和 A 服务器粘到了一块，这就是粘性 session 机制。

**优点：** 简单，不需要对 session 做任何处理。 
 **缺点：** 缺乏容错性，如果当前访问的服务器发生故障，用户被转移到第二个服务器上时，他的 session 信息都将失效。 
 **适用场景：** 发生故障对客户产生的影响较小；服务器发生故障是低概率事件 。
 **实现方式：** 以 Nginx 为例，在 upstream 模块配置 ip_hash 属性即可实现粘性 session。



#### 3. session 共享（常用）

- 使用分布式缓存方案比如 Memcached 、Redis 来缓存 session，但是要求 Memcached 或 Redis 必须是集群
- 把 session 放到 Redis 中存储，虽然架构上变得复杂，并且需要多访问一次 Redis ，但是这种方案带来的好处也是很大的：
  - 实现了 session 共享；
  - 可以水平扩展（增加 Redis 服务器）；
  - 服务器重启 session 不丢失（不过也要注意 session 在 Redis 中的刷新/失效机制）；
  - 不仅可以跨服务器 session 共享，甚至可以跨平台（例如网页端和 APP 端）



![img](images/16f523a04fb8b4b8tplv-t2oaga2asx-zoom-in-crop-mark3024000.awebp)





#### 4. session 持久化

- 将 session 存储到数据库中，保证 session 的持久化

**优点：** 服务器出现问题，session 不会丢失 
 **缺点：** 如果网站的访问量很大，把 session 存储到数据库中，会对数据库造成很大压力，还需要增加额外的开销维护数据库。



### **只要关闭浏览器 ，session 真的就消失了？**

不对。对 session 来说，除非程序通知服务器删除一个 session，否则服务器会一直保留，程序一般都是在用户做 log off 的时候发个指令去删除 session。
然而浏览器从来不会主动在关闭之前通知服务器它将要关闭，因此服务器根本不会有机会知道浏览器已经关闭，之所以会有这种错觉，是大部分 session 机制都使用会话 cookie 来保存 session id，而关闭浏览器后这个 session id 就消失了，再次连接服务器时也就无法找到原来的 session。如果服务器设置的 cookie 被保存在硬盘上，或者使用某种手段改写浏览器发出的 HTTP 请求头，把原来的 session id 发送给服务器，则再次打开浏览器仍然能够打开原来的 session。
恰恰是**由于关闭浏览器不会导致 session 被删除，迫使服务器为 session 设置了一个失效时间，当距离客户端上一次使用 session 的时间超过这个失效时间时，服务器就认为客户端已经停止了活动，才会把 session 删除以节省存储空间。**





## JWT介绍

### JWT组成部分

jwt是由三部分组成：

* **头部-Header**

  * ```js
    # alg是签名算法，默认是HS256，
    # typ是token类型，一般JWT默认为JWT
    {
        "alg": "HS256",
        "typ": "JWT"
    }
    ```

  * 然后按照此规则将头部信息进行base64编码，构成JWT第一部分

* **载荷-payload**

  * ```js
    // payload 就是存放有效信息的地方
    {
        "key0": "value0",
        "key1": "value1"，
        // "iss": "margin",
        ...
    }
    ```

  * | 字段名                | 描述     |
    | --------------------- | -------- |
    | iss(issuer)           | 签发人   |
    | exp (expiration time) | 过期时间 |
    | sub (subject)         | 主题     |
    | aud (audience)        | 受众     |
    | nbf (Not Before)      | 生效时间 |
    | iat (Issued At)       | 签发时间 |
    | jti (JWT ID)          | 编号     |

    这7个属性可以放到payload中作为payload的组成部分

  * payload 会进行base64编码，构成JWT第二部分

* **签证-Singnature**

  * Signature 部分是对前两部分的签名，防止数据篡改。

  * 需要指定一个密钥（secret）。这个密钥只有服务器才知道，不能泄露给用户。然后，使用 Header 里面指定的签名算法（默认是 HMAC SHA256）。

  * ```js
    let encodedString = base64UrlEncode(header) + '.' + base64UrlEncode(payload);
    let secret = "秘钥";
    let singnature = HMACSHA256(encodedString, secret);
    ```



**代码实现生成token**

1、生成header 

 将json字符串转为base64

```js
// node 生成base64 浏览器使用atob	
const headerBuffer = Buffer.from(
    JSON.stringify({
        alg: "HS256",
        typ: "JWT",
    })
);
const header = headerBuffer.toString("base64");
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

2、生成payload

将json字符串转为base64

```js
const headerBuffer = Buffer.from(
    JSON.stringify({ username: "zs", age: 18, iat: "1678952863" })
);
const header = headerBuffer.toString("base64");
// eyJ1c2VybmFtZSI6InpzIiwiYWdlIjoxOCwiaWF0IjoiMTY3ODk1Mjg2MyJ9
```

3、生成Singnature

```js
const singnature = CryptoJS.HmacSHA256(
    `${header}.${payload}`,
    privateKey
).toString(CryptoJS.enc.Base64url);
// v8IppGUVUjWNt4IMPO4b8woKfgpa_FvWR2KhYg0A9CM
const token = `${header}.${payload}.${singnature}`;
console.log(token);
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InpzIiwiYWdlIjoxOCwiaWF0IjoiMTY3ODk1Mjg2MyJ9.v8IppGUVUjWNt4IMPO4b8woKfgpa_FvWR2KhYg0A9CM
```

![image-20230316170054994](images/image-20230316170054994.png)

将我们生成的token放到`https://jwt.io/`中进行校验、结果显示成功



### JWT无感刷新方案

**jwt的无感刷新原理：**

​	其实就是jwt在过期或即将获取前、获取新的token、让用户的凭证、让用户感觉不出来

**常见的token续期方案：**

* 1、返回access_token时、再返回一个过期时间
  * 前端可以在请求之前先判断token是否即将过期？在即将过期之前重新获取新的access_token
  * 缺点：客户端时间不准时、实际的token有可能过期
* 2、前端每隔一段时间、轮询查询access_token是否过期
  * 前端每隔30s进行轮询查询access_token是否即将过期？在即将过期之前重新获取新的access_token
  * 缺点：时间粒度过小时、增加带宽和服务端压力、粒度过大时；token可能已过期、但是显示过期
* 3、后台返回的access_token是用不过期的、但是后台将access_token作为key存储到redis中、并且给定过期时间、当我们下次访问时、没有过期的话重新更新过期时间
  * 优点: 后台可以控制token什么时候失效、纯后端来做
  * 缺点：需要安装redis、并且增加内存的占用
* 4、返回`access_token`时、再返回一个`refresh_token` 刷新token  (`refresh_token`的有效时长大于 `access_token`； 比如 `access_token`有效2h, `refresh_token`有效24小时)
  * 当`access_token`过期时，再发送一个请求携带者`refresh_token`、来获取新的token

![image-20230317103737254](images/image-20230317103737254.png)



> 疑问： 为什么要用两个`token`, 一个`access_token`不行吗？ 
>
> 答：不行，试想一下，如果仅有一个`access_token`， 那么逻辑就是`access_token`过期后，后台就要返回一个新的`access_token`，那就相当于`access_token`永不过期；一旦`access_token`泄漏、那拿到`access_token`的人就能永远能够登陆进后台、这种是非常危险的；
>
> 疑问： `refresh_token`泄漏了怎么办？
>
> 答： `refresh_token`设置的有过期时间、一旦超过过期时间，就不能够获取到最新的`access_token`； 并且`refresh_token`仅在`access_token`失效时才进行请求；执行的次数比较少、泄漏的风险也比较少
>
> 疑问： `access_token`泄漏了怎么办？
>
> 答： `access_token`设置的有过期时间、一旦超过过期时间，就不能登陆; 并且过期时间也比较短







前三种方案都比较简单、我们这次值模拟第四种方案： `refresh_token` 刷新`token`

具体流程如下：

![image-20230317141635897](images/image-20230317141635897.png)

* 1、初次登录时、后台返回两个`token` 分别是： `access_token` 和 `refresh_token`
* 2、下次请求的时候在请求头中携带`access_token`、后台进行判断`access_token`是否有效？
  * 有效：正常返回值
  * 无效： 返回状态码为`401`
* 3、在响应拦截器中、判断状态码为`401`时、携带 `refresh_token`并发送刷新`token`请求；后台校验 `refresh_token`是否有效？ 
  * 无效： 返回错误标识
  * 有效：返回`access_token`
* 4、判断返回的值存在`access_token`时、携带业务逻辑的请求`config`并重新返送请求、将接受到的结果再重新返回

**代码实现**

后台代码：

```js
// jwt-utils/index.js

const jwt = require("jsonwebtoken");
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


module.exports = {
  createToken,
  verifyToken,
};

```

```js
// utils/index.js
// 解析req获取请求头中的token
const getTokenByReq = (req) => {
  const authorization = req.headers.authorization || "";
  const token = authorization.split(" ")[1];
  return token;
};

module.exports = {
  getTokenByReq,
};

```

```js
// app.js

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

// 通过refresh_token 获取access_token
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

```

前端代码

```js
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Document</title>
    <script
      src="https://code.jquery.com/jquery-3.6.4.js"
      integrity="sha256-a9jBBRygX1Bh5lt8GZjXDzyOB+bWve9EiO7tROUtj/E="
      crossorigin="anonymous"
    ></script>
    <script src="https://cdn.bootcdn.net/ajax/libs/axios/0.21.1/axios.min.js"></script>
    <style>
      * {
        padding: 0;
        margin: 0;
      }
      .card {
        padding: 15px;
        margin: 15px;
        box-shadow: 3px 3px 5px #eaeaea, -3px -3px 5px #eaeaea;
        border-radius: 8px;
      }
      button {
        padding: 3px 12px;
        background-color: #255252;
        border: none;
        color: #fff;
        cursor: pointer;
      }
      textarea {
        border: 1px solid #999;
        border-radius: 6px;
      }
    </style>
  </head>
  <body>
    <div class="card">
      <textarea name="" id="login-text" cols="30" rows="10">
        {
          "name": "zs",
          "password": "123456"
        }
      </textarea>
      <button id="login">登录</button>
    </div>

    <div class="card">
      <textarea name="" id="list-text" cols="30" rows="10"> </textarea>
      <button id="getList">获取list</button>
    </div>

    <script>
      const ACCESS_TOKEN_KEY = "ACCESS_TOKEN_KEY";
      const REFRESH_TOKEN_KEY = "REFRESH_TOKEN_KEY";
      const serve = axios.create({
        timeout: 2000,
      });

      serve.interceptors.request.use(
        (config) => {
          console.log("config", config);
          config.headers.Authorization = `bearer ${
            window.localStorage.getItem(ACCESS_TOKEN_KEY) || ""
          }`;
          return config;
        },
        (error) => Promise.reject(err)
      );

      serve.interceptors.response.use(
        (response) => {
          return response.data;
        },
        async (error) => {
          // 判断状态码为401表示access_token 已过期
          if (error.response.status === 401) {
            // 从本地中取出刷新token  refresh_token
            const refresh_token =
              window.localStorage.getItem(REFRESH_TOKEN_KEY);
            // 请求refreshToken 通过refresh_token获取 最新的access_token
            const { data } = await axios.get("/refreshToken", {
              params: {
                refresh_token,
              },
            });
            // 判断返回结果
            if (data.code === 200) {
              // 将新的 access_token缓存到本地
              window.localStorage.setItem(ACCESS_TOKEN_KEY, data.access_token);
              // 重新携带config、发起请求（authorization需要使用最新的access_token）
              const res = await axios({
                ...error.config,
                headers: {
                  ...error.config.headers,
                  Authorization: `bearer ${data.access_token}`,
                },
              });
              // 并将结果给返回出错
              return res.data;
            }
          }
          return Promise.reject(error);
        }
      );

      $(function () {
        // 登录
        $("#login").on("click", async () => {
          const { refresh_token, access_token } = await serve.get("/login", {
            params: JSON.parse($("#login-text").val()),
          });
          window.localStorage.setItem(ACCESS_TOKEN_KEY, access_token);
          window.localStorage.setItem(REFRESH_TOKEN_KEY, refresh_token);
        });

        // 登录
        $("#getList").on("click", async () => {
          const { list } = await serve.get("/getList");
          $("#list-text").val(JSON.stringify(list, null, 2));
        });
      });
    </script>
  </body>
</html>

```

> 核心代码就是在`serve.interceptors.response`中的处理
>
> 在access_token校验失败后、重新发起请求刷新token
>
> 拿到最新的token之后再次发送之前失败的请求，并且将结果返回



在本地实验的、我们设置`access_token`有效期是`5s` 、`refresh_token`有效期是`1h`;下面看一下实验结果

![20230317_150300](images/20230317_150300.gif)

> 上图分析： 
>
> 首先登陆后、立即获取list，能够获取到后台返回的信息
>
> 然后等5s后（此时access_token已失效）， 再次点击获取list 
>
> ​	我们可以看到、`getList`先请求失败后、立即请求`/refreshToken`接口
>
> ​	然后在请求`getList`接口、返回数据；并且正常展示
> **整个过程用户是无感的**



## jwt 和 cookie-session的优缺点

**cookie-session**

* 优点：
  * 前端请求时可以自动在请求头中携带、不需要做额外的处理、保存也是自动保存到浏览器

* 缺点：
  * 1、session占用服务端内存
  * 2、服务端做负载均衡时、用户访问时会出现未授权的情况（需要使用redis存放共有的session信息）
  * 3、容易遭受csrf（跨站请求伪造）攻击
  * 4、可以自动续期

**jwt**

* 优点：
  * 1、不占用服务端内存、所有的信息保存到token中、然后在服务端通过秘钥进行解密
  * 2、服务端做负载均衡也一样能够解析token、不用额外处理
  * 3、可以避免csrf（跨站请求伪造）攻击
* 缺点：
  * 1、非ajax请求的需要在请求参数中携带token
  * 2、一旦生成token、就无法销毁（可以在redis中设置过期时间可以解决）