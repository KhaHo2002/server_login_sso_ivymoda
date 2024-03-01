import { v4 as uuidv4 } from 'uuid';
import loginRegisterService from '../service/loginRegisterService';
import { createJWT } from '../middleware/JWTAction';

const handleLoginController = (req, res) => {
    const { serviceURL } = req.query;
    return res.render("login.ejs", { serviceURL: serviceURL });
}

const handleVerifyTokenSSO = async (req, res) => {
    const ssoToken = req.body.ssoToken;
    try {
        if (req.user && req.user.code === ssoToken) {
            const refresh_token = uuidv4();
            await loginRegisterService.updateUserRefreshToken(req.user.email, refresh_token);
            // await loginRegisterService.updateUserRefreshToken(req.user.email);

            let payload = {
                email: req.user.email,
                groupWithRoles: req.user.groupWithRoles,
                username: req.user.username
            }
            let access_token = createJWT(payload);
            //set cookies
            res.cookie('access_token', access_token, { maxAge: 2000 * 1000, httpOnly: true, domain: process.env.COOKIE_DOMAIN, path: "/" });
            res.cookie('refresh_token', refresh_token, { maxAge: 4000 * 1000, httpOnly: true, domain: process.env.COOKIE_DOMAIN, path: "/" });

            const dataReponse = {
                access_token: access_token,
                refresh_token: refresh_token,
                groupWithRoles: req.user.groupWithRoles,
                email: req.user.email,
                username: req.user.username
            }

            //destroy session
            req.session.destroy(function (err) {
                req.logout(function () { });
            });


            return res.status(200).json({
                EM: 'OK',
                EC: 0,
                DT: dataReponse
            })
        }
        else {
            return res.status(401).json({
                EM: 'No match',
                EC: 2
            })
        }
    } catch (error) {
        return res.status(500).json({
            EM: 'something wrong server...',
            EC: 1
        })
    }

    // else {
    //     return res.status(200).json({
    //         EM: 'No match',
    //         EC: 1
    //     })
    // }
}

module.exports = {
    handleLoginController,
    handleVerifyTokenSSO
}