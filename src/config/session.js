
import session from 'express-session';
import Sequelize from 'sequelize';
import passport from 'passport';

const configSession = (app) => {
    var SequelizeStore = require("connect-session-sequelize")(session.Store);

    // create database, ensure 'sqlite3' in your package.json
    const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER_NAME, process.env.DB_PASSWORD, {
        host: process.env.DB_HOST,
        dialect: process.env.DB_DIALECT,
        logging: false,
        define: {
            freezeTableName: true
        },
        timezone: "+07:00"
    });
    const myStore = new SequelizeStore({
        db: sequelize,
    });
    app.use(
        session({
            secret: "keyboard cat",
            store: myStore,
            saveUninitialized: false,
            expiration: 3000 * 1000,
            cookie: { expires: 3000 * 1000 },
            resave: false, // we support the touch method so per the express-session docs this should be set to false
            proxy: true, // if you do SSL outside of node.
        })
    );
    // tạo database session trong db
    myStore.sync();
    app.use(passport.authenticate('session'));




    // mã hóa data
    passport.serializeUser(function (user, cb) {
        process.nextTick(function () {
            cb(null, user);
        });
    });
    // giải mã hóa
    passport.deserializeUser(function (user, cb) {
        process.nextTick(function () {
            return cb(null, user);
            // khúc này là user được gán vô req luôn :)))
        });
    });
}



export default configSession;