require('dotenv').config();
import db from '../models/index';
import bcrypt from 'bcryptjs';
import { Op } from 'sequelize';
import { getGroupWithRoles } from './JWTService';
import { createJWT } from '../middleware/JWTAction';
import { v4 as uuidv4 } from 'uuid';
const salt = bcrypt.genSaltSync(10);

const hashUserPassword = (userPassword) => {
    let hashPassword = bcrypt.hashSync(userPassword, salt);
    return hashPassword;
}

const checkEmailExist = async (userEmail) => {
    let user = await db.User.findOne({
        where: { email: userEmail }
    })

    if (user) {
        return true;
    }
    return false;
}

const checkPhoneExist = async (userPhone) => {
    let user = await db.User.findOne({
        where: { phone: userPhone }
    })

    if (user) {
        return true;
    }
    return false;
}

const registerNewUser = async (rawUserData) => {
    try {
        //check email/phonenumber are exist
        let isEmailExist = await checkEmailExist(rawUserData.email);
        if (isEmailExist === true) {
            return {
                EM: 'The email is already exist',
                EC: 1
            }
        }
        let isPhoneExist = await checkPhoneExist(rawUserData.phone);
        if (isPhoneExist === true) {
            return {
                EM: 'The phone number is already exist',
                EC: 1
            }
        }
        //hash user password
        let hashPassword = hashUserPassword(rawUserData.password);

        //create new user
        await db.User.create({
            email: rawUserData.email,
            username: rawUserData.username,
            password: hashPassword,
            phone: rawUserData.phone,
            groupId: 4
        })

        return {
            EM: 'A user is created successfully!',
            EC: '0'
        }

    } catch (e) {
        console.log(e)
        return {
            EM: 'Somthing wrongs in service...',
            EC: -2
        }
    }
}

const checkPassword = (inputPassword, hashPassword) => {
    return bcrypt.compareSync(inputPassword, hashPassword); // true or false
}

const handleUserLogin = async (rawData) => {
    try {
        let user = await db.User.findOne({
            where: {
                [Op.or]: [
                    { email: rawData.username }
                ]
            }
        })

        if (user) {
            let isCorrectPassword = checkPassword(rawData.password, user.password);
            if (isCorrectPassword === true) {
                let groupWithRoles = await getGroupWithRoles(user);
                const code = uuidv4();
                // let payload = {
                //     email: user.email,
                //     groupWithRoles,
                //     username: user.username,
                // }
                // let token = createJWT(payload);
                return {
                    EM: 'ok!',
                    EC: 0,
                    DT: {
                        code: code,
                        groupWithRoles,
                        email: user.email,
                        username: user.username
                    }
                }
            }
            else {
                return {
                    EM: 'Your email/password number or password is incorrect!',
                    EC: 1,
                    DT: ''
                }
            }
        }


        return {
            EM: 'Your email/password number or password is incorrect!',
            EC: 1,
            DT: ''
        }


    } catch (error) {
        console.log(error)
        return {
            EM: 'Somthing wrongs in service...',
            EC: -2
        }
    }
}

// const updateUserRefreshToken = async (email, token) => {
//     if (email && token) {
//         let user = await db.User.update(
//             {
//                 refreshToken: token
//             },
//             {
//                 where: { email: email }
//             }

//         );
//     }
//     else {
//         return "Not found";
//     }
//     // try {
//     //     let user = await db.User.update(
//     //         {
//     //             refreshToken: token
//     //         },
//     //         {
//     //             where: { email: email }
//     //         }

//     //     );

//     // } catch (error) {
//     //     console.log(error);
//     // }
// }

const updateUserRefreshToken = async (email, token) => {
    try {
        let user = await db.User.update(
            {
                refreshToken: token
            },
            {
                where: { email: email }
            }
        );

        if (user[0] === 0) {
            throw new Error("User not found"); // Handle the case where no user was updated
        }
    } catch (error) {
        return error
    }
};

const getUserRefreshToken = async (sendToken) => {
    if (sendToken) {
        let user = await db.User.findOne({
            where: {
                refreshToken: sendToken
            }
        });

        if (user) {
            let groupWithRoles = await getGroupWithRoles(user);
            return {
                email: user.email,
                groupWithRoles: groupWithRoles,
                username: user.username
            };
        }
        else {
            return "Not found user";
        }
    } else {
        return "Not found";
    }
};
export default getUserRefreshToken;
module.exports = {
    registerNewUser, handleUserLogin, hashUserPassword, checkEmailExist, checkPhoneExist,updateUserRefreshToken

}

// module.exports = updateUserRefreshToken;
