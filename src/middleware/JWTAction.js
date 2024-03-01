
require("dotenv").config();
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import updateUserRefreshToken from "../service/loginRegisterService";
import getUserRefreshToken from "../service/loginRegisterService";

const nonSecurePaths = ['/logout', '/login', '/register', '/verify-service'];

const createJWT = (payload) => {
    let key = process.env.JWT_SECRET;
    let token = null;
    try {
        token = jwt.sign(payload, key, {
            expiresIn: process.env.JWT_EXPIRES_IN
        });
    } catch (err) {
        console.log(err)
    }
    return token;
}

const verifyToken = (token) => {
    let key = process.env.JWT_SECRET;
    let decoded = null;

    try {
        decoded = jwt.verify(token, key);
    } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
            return "TokenExpiredError";
        }
        console.log(err);
    }
    return decoded;
}

const extractToken = (req) => {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
    }
    return null;
}

const checkUserJWT = async (req, res, next) => {
    if (nonSecurePaths.includes(req.path)) return next();

    let cookies = req.cookies;
    let tokenFromHeader = extractToken(req);

    if ((cookies && cookies.access_token) || tokenFromHeader) {
        let access_token = cookies && cookies.access_token ? cookies.access_token : tokenFromHeader;
        let decoded = verifyToken(access_token);
        if (decoded && decoded !== "TokenExpiredError") {
            decoded.access_token = access_token;
            decoded.refresh_token = cookies.refresh_token;
            req.user = decoded;
            next();
        }

        else if (decoded && decoded === "TokenExpiredError") {
            if (cookies && cookies.refresh_token) {
                let data = await handleRefreshToken(cookies.refresh_token);
                let newAccessToken = data.newAccessToken;
                let newRefreshToken = data.newRefreshToken;

                if (newAccessToken && newRefreshToken) {

                    res.cookie('access_token', newAccessToken, { maxAge: 2000 * 1000, domain: process.env.COOKIE_DOMAIN, path: "/" });
                    res.cookie('refresh_token', newRefreshToken, { maxAge: 4000 * 1000, domain: process.env.COOKIE_DOMAIN, path: "/" });
                    //trả ra lỗi 405 để client check điều kiện là mã lỗi 405 để retry api
                    return res.status(405).json({
                        errorCode: -1,
                        data: '',
                        status: 'Need retry with new token'
                    })
                }
            }
            else {
                return res.status(401).json({
                    EC: -3,
                    DT: '',
                    EM: 'Not authenticated the user'
                })
            }
        }

        else {
            return res.status(401).json({
                EC: -2,
                DT: '',
                EM: 'Not authenticated the user'
            })
        }
    }
    else {
        return res.status(401).json({
            EC: -1,
            DT: '',
            EM: 'Not authenticated the user'
        })
    }
}

const checkUserPermission = (req, res, next) => {
    if (nonSecurePaths.includes(req.path) || req.path === '/account') return next();

    if (req.user) {
        let email = req.user.email;
        let roles = req.user.groupWithRoles.Roles;
        let currentUrl = req.path;
        if (!roles || roles.length === 0) {
            return res.status(403).json({
                EC: -1,
                DT: '',
                EM: `you don't permission to access this resource...`
            })
        }

        let canAccess = roles.some(item => item.url === currentUrl || currentUrl.includes(item.url));
        if (canAccess === true) {
            next();
        } else {
            return res.status(403).json({
                EC: -1,
                DT: '',
                EM: `you don't permission to access this resource...`
            })
        }
    } else {
        return res.status(401).json({
            EC: -1,
            DT: '',
            EM: 'Not authenticated the user'
        })
    }
}


const checkService = (req, res, next) => {
    let tokenFromHeader = extractToken(req);

    if (tokenFromHeader) {
        let access_token = tokenFromHeader ? tokenFromHeader : '';
        let decoded = verifyToken(access_token);
        if (decoded) {
            return res.status(200).json({
                EC: 0,
                DT: '',
                EM: 'Verify user success'
            })
        } else {
            return res.status(401).json({
                EC: -1,
                DT: '',
                EM: 'Not authenticated the user'
            })
        }
    }
    else {
        return res.status(401).json({
            EC: -1,
            DT: '',
            EM: 'Not authenticated the user'
        })
    }
}


const handleRefreshToken = async (refreshToken) => {
    let newAccessToken = '', newRefreshToken = '';
    try {
        let user = await getUserRefreshToken(refreshToken);
        if (user) {
            let payloadAccessToken = {
                email: user.email,
                groupWithRoles: user.groupWithRoles,
                username: user.username
            }
            newAccessToken = createJWT(payloadAccessToken);
            newRefreshToken = uuidv4();
            //update refreshToken in table user when refreshToken expired
            let data = await updateUserRefreshToken(payloadAccessToken.email, newRefreshToken);
        }
        return {
            newAccessToken, newRefreshToken
        }
    } catch (error) {
        throw error;
    }

}

module.exports = {
    createJWT, verifyToken, checkUserJWT, checkUserPermission, checkService
}