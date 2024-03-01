
import passport from 'passport';
import LocalStrategy from 'passport-local';
import loginRegisterService from '../service/loginRegisterService';

// import flash from 'connect-flash';

const configPassport = () => {
    passport.use(new LocalStrategy({
        passReqToCallback: true
    },
        async (req, username, password, cb) => {
            const rawData = {
                username: username,
                password: password
            }
            // console.log(rawData,"??");
            let res = await loginRegisterService.handleUserLogin(rawData);
            if (res && res.EC === 0) {
                return cb(null, res.DT);
            }
            else {
                return cb(null, false, { message: res.EM });
            }
        }
    ))
}

const handleLogout = (req, res, next) => {
    // req.session.destroy(function (err) {
    //     req.logout();
    //     res.redirect('/');
    // })
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
}

module.exports = {
    configPassport,
    handleLogout
}