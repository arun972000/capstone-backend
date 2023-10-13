import express, { json } from "express";
import jwt from "jsonwebtoken"
import { Usermodel } from "../Mongoose/model.js";
import { v4 } from "uuid";
import bcrypt from "bcrypt"
import { mailOptions, transporter } from "../nodemailer.js";

const userRoutes = express.Router()

userRoutes.use(json())


userRoutes.post("/register", async (req, res) => {
    try {
        const payload = req.body
        const isUser = await Usermodel.findOne({ email: payload.email })

        if (isUser) {
            return res.status(409).send("user already exists")
        }
        bcrypt.hash(payload.password, 10, async (err, hash) => {
            const newUser = new Usermodel({ ...payload, id: v4(), password: hash })
            await newUser.save()
            res.status(201).send("Registered success")
        })


    } catch (err) {
        res.status(500).send(err.message)
    }
})

userRoutes.post("/login", async (req, res) => {
    try {
        const payload = req.body;
        const user = await Usermodel.findOne({ email: payload.email });
        if (!user) {
            return res.status(404).send("no user found")
        }
        bcrypt.compare(payload.password, user.password, async (err, result) => {
            if (!result) {
                return res.status(400).send("invalid credentials")
            } else {
                const response = user.toJSON()
                delete response.password
                res.status(201).send(response)
            }
        })
    } catch (err) {
        res.status(500).send(err.message)
    }
})

userRoutes.post("/verifyPassword", async (req, res) => {
    try {
        const { email } = req.body;
        const user = await Usermodel.findOne({ email });

        if (!user) {
            return res.status(404).send("no user found")
        }
        const token = jwt.sign({ email: user.email }, process.env.JWT_KEY, { expiresIn: "1d" })
        user.resetPasswordToken = token
        await user.save()
        const link = `http://localhost:5173/verify/${token}`
        transporter.sendMail({ ...mailOptions, to: user.email, text: link }, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent: ' + info.response);
            }
        });
        res.status(201).send("mail sent")
    } catch (err) {
        res.status(500).send(err)
    }
})


userRoutes.put("/resetPassword/:token", async (req, res) => {
    try {
        const { token } = req.params;
        const user = await Usermodel.findOne({ resetPasswordToken: token });

        if (!user) {
            return res.status(400).json({
                login: false,
                data: 'Invalid or expired token'
            });
        }

        jwt.verify(token, process.env.JWT_KEY, (err, decoded) => {
            if (err) {
                return res.status(400).json({
                    login: false,
                    data: 'Invalid or expired token'
                });
            }

            user.resetPasswordToken = undefined;
            user.save();

            res.status(201).json({
                login: true,
                data: decoded
            });
        });
    } catch (err) {
        res.status(500).send(err.message);
    }
});



export default userRoutes