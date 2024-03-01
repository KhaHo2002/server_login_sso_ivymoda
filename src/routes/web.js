import express from "express";
import homeController from '../controller/homeController';
import apiController from '../controller/apiController';
import loginController from '../controller/loginController';
import passport from 'passport';
import checkUser from '../middleware/checkUser';
import passportController from '../controller/passportController';

const router = express.Router();

/**
 * 
 * @param {*} app : express app
 */

const initWebRoutes = (app) => {
    //path, handler
    router.get("/", checkUser.handleCheckLogin, homeController.handleHelloWord);
    router.get("/user", homeController.handleUserPage);
    router.post("/users/create-user", homeController.handleCreateNewUser);
    router.post("/delete-user/:id", homeController.handleDelteUser)
    router.get("/update-user/:id", homeController.getUpdateUserPage);
    router.post("/user/update-user", homeController.handleUpdateUser);

    //rest api
    //GET - R, POST- C, PUT - U, DELETE - D
    router.get("/api/test-api", apiController.testApi);


    //LOGIN SSO
    router.get("/login", checkUser.handleCheckLogin, loginController.handleLoginController);

    // router.post('/login', passport.authenticate('local', {
    //     successRedirect: '/1',
    //     failureRedirect: '/login'
    // }));


    router.post('/login', function (req, res, next) {
        passport.authenticate('local', function (error, user, info) {

            if (error) {
                return res.status(500).json(error);
            }
            if (!user) {
                return res.status(401).json(info.message);
            }
            // Khi mà login, vì có middleware nên nó ko lưu user, vì thế cần gọi hàm req.login để nó lưu user vào session
            req.login(user, function (err) {
                if (err) return next(err);
                return res.status(200).json({ ...user, redirectURL: req.body.serviceURL });
            })
        })(req, res, next);
    });
    router.post('/verify-token', loginController.handleVerifyTokenSSO);

    router.post('/logout', passportController.handleLogout);

    return app.use("/", router);
}

export default initWebRoutes;