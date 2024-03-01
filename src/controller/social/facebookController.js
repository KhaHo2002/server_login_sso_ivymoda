
import passport from 'passport';
import LocalStrategy from 'passport-local';
import loginRegisterService from '../service/loginRegisterService';

// import flash from 'connect-flash';

const configPassportFacebook = () => {
    passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_APP_CLIENT_SECRET,
        callbackURL: process.env.FACEBOOK_APP_REDIRECT_LOGIN
    },
        function (accessToken, refreshToken, profile, cb) {
            User.findOrCreate({ facebookId: profile.id }, function (err, user) {
                return cb(err, user);
            });
        }
    ));
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
    configPassportFacebook,
    handleLogout
}