import express from "express";
// import _ from 'lodash';
import Auth from "../models/authM.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import checkauth from "../middleware/authT.js";
import nodemailer from "nodemailer";
import moment from "moment";
import dotenv from "dotenv";
import multer from "multer";
import fileUpload from "express-fileupload";
import { v2 as cloudinary } from "cloudinary";
import { url } from "inspector";
import adduservali from "../validation/authValidation.js";
import adminauth from "../middleware/adminT.js";

dotenv.config();
const authrouter = express.Router();

//CLOUD CONDITIONS..................
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

//BCRYPT PASSWORD USE THIS METHOD START
const secure = async (password) => {
  try {
    const passwordhash = await bcrypt.hash(password, 10);
    return passwordhash;
  } catch (error) {
    res.status(400).send({ message: "error" });
  }
};
//BCRYPT PASSWORD USE THIS METHOD END
const createtoken = async (id, res) => {
  try {
    // const tokn = await Jwt.sign({ _id: id }, config.secret)

    const tokn = await jwt.sign({ _id: id }, "privatekey", {
      expiresIn: "24h",
    });

    return tokn;
  } catch (error) {
    res.send("error");
  }
};
//verify mail register time start
const sentverifymail = async (fullName, email, user_id) => {
  try {
    const transporter = nodemailer.createTransport({
      port: 465, // true for 465, false for other ports
      host: "smtp.gmail.com",
      auth: {
        user: process.env.USER_id,
        pass: process.env.USER_PASS,
      },
      secure: true,
    });
    const mailoptions = {
      from: process.env.USER_id,
      to: process.env.USER_id,
      subject: "for email varifiaction",
      html:
        "<p> hii " +
        fullName +
        ', please click to verify <a href="  https://sfddfsd.herokuapp.com/verify?id=' +
        user_id +
        '">verify</a>your mail</p>',
    };
    transporter.sendMail(mailoptions, function (err, info) {
      if (err) console.log(err);
      else res.status(200).send(mailoptions);
    });
  } catch (error) {
    res.status(400).send("error");
  }
};

// verify time mail sent
const verify = async (email) => {
  const transporter = nodemailer.createTransport({
    port: 465, // true for 465, false for other ports
    host: "smtp.gmail.com",
    auth: {
      user: process.env.USER_id,
      pass: process.env.USER_PASS,
    },
    secure: true,
  });
  const mailoptions = {
    from: process.env.USER_id,
    to: email,
    subject: "for varifiaction message",
    html: "<p> your account was varified by admin </p>",
  };
  transporter.sendMail(mailoptions, function (err, info) {
    if (err) console.log(err);
    else res.status(200).send(mailoptions);
  });
};

var mails = " "; // varify time mail sent ke ley blank varible

// varify route start..............
authrouter.get("/verify", async (req, res) => {
  try {
    const update = await Auth.updateOne(
      { _id: req.query.id },
      { $set: { isVarified: 1 } }
    );

    res.status(200).send({ success: "welcome user mail varify" });

    verify(mails);
  } catch (error) {
    res.status(400).send("err");
  }
});

//FILE STORAGE QUERY START........................
const storage = multer.diskStorage({
  //  destination: './public/assets/images',

  filename: (req, file, cb) => {
    cb(
      null,
      new Date().toISOString().replace(/:/g, "-") + "-" + file.originalname
    );
  },
});
//FILE STORAGE QUERY END....................................................................................

//FILE FILTER QUERY START....................................................................................
const filefilter = (req, file, cb) => {
  if (
    file.mimetype === "image/png" ||
    file.mimetype === "image/jpg" ||
    file.mimetype === "image/jpeg" ||
    file.mimetype === "application/pdf"
  ) {
    cb(null, true);
  } else {
    cb(null, false);
  }
};
const upload = multer({ storage: storage, fileFilter: filefilter });

//register route start.....................
authrouter.post("/register", adduservali, async (req, res) => {
  try {
    const file = req.files.image;
    cloudinary.uploader.upload(file.tempFilePath, async (err, result) => {
      const spassword = await secure(req.body.password);

      const files = new Auth({
        image: result.secure_url,
        cloudinary_id: result.public_id,
        fullName: req.body.fullName,
        email: req.body.email,
        password: spassword,
        confirmPassword: spassword,
      });
      const userdata = await Auth.findOne({ email: req.body.email });

      if (userdata) {
        res.status(400).send({ error: "user already exist" });
      } else {
        const userdata1 = await files.save();
        mails = userdata1.email;
        res
          .status(200)
          .send({ message: "please wait your mail varify by admin" });
        sentverifymail(req.body.name, req.body.email, userdata1._id);
      }
    });
  } catch (error) {
    res.status(400).send("something wrong");
  }
});

//post method user register HIDE PASSWORD and BCRYPT PASSWORD START......................................
authrouter.post("/login", async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).send({ error: "please fill the proper field " });
  } else {
    let user = await Auth.findOne({ email: req.body.email });

    if (!user) {
      return res.status(404).send({ error: "invalid email please try again" });
    } else if (user.isVarified === 0) {
      res.status(400).send({ error: "not allow by admin" });
    } else {
      const checkpassword = await bcrypt.compare(
        req.body.password,
        user.password
      );

      if (!checkpassword) {
        return res
          .status(404)
          .send({ error: "invalid password please try again" });
      }
      const token = await createtoken(user._id);

      const date = moment().format("L");

      let Id = user._id;
      res.status(200).send({ success: "😉welcome user..!!", token, Id, date });
      // res.status(200).send({ success: "😉welcome user..!!", token, Id, date })
    }
  }
});

// get the user register with id.............................................................................................
authrouter.get("/user/:id", checkauth, async (req, res) => {
  try {
    const _id = req.params.id;

    const data = await Auth.findById(_id);

    (data.password = undefined),
      (data.confirmPassword = undefined),
      (data.isVarified = undefined),
      (data.isAdmin = undefined);

    res.status(200).send({ status: "success", details: data });
  } catch (error) {
    res.status(400).send({
      status: "Bad Request",
      details: "",
      message: "something wrong user not found in data base...",
    });
  }
});

//update the user register with id...........................................................................................
authrouter.put("/user/update/:id", checkauth, async (req, res) => {
  try {
    const { fullName, email } = req.body;
    const file = req.files.image;
    let user = await Auth.findById(req.params.id);
    const dis = await cloudinary.uploader.destroy(file.tempFilePath);

    let result;
    if (dis) {
      result = await cloudinary.uploader.upload(file.tempFilePath);
    }

    const data = {
      fullName,
      email,
      image: result?.secure_url || user.image,
      cloudinary_id: result?.public_id || user.cloudinary_id,
    };

    user = await Auth.findByIdAndUpdate(req.params.id, data, { new: true });

    (user.password = undefined),
      (user.confirmPassword = undefined),
      (user.isVarified = undefined),
      (user.isAdmin = undefined);

    res.status(200).send({ status: "success", updateDetails: user });
  } catch (error) {
    res.status(400).send({
      status: "Bad Request",
      updateData: "",
      message: "something wrong user not found...",
    });
  }
});

//delete the register user by id...................................................................
authrouter.delete(
  "/user/delete/:id",
  [checkauth, adminauth],
  async (req, res) => {
    try {
      const id = req.params.id;
      let user = await Auth.findByIdAndDelete(id);

      if (user) {
        return res
          .status(200)
          .send({ status: "success", message: "deleted successfully" });
      } else {
        res.status(404).send({ status: "success", message: "not found" });
      }
    } catch (error) {
      res.status(400).send({
        status: "Bad Request",
        deleteData: "",
        message: error.message,
      });
    }
  }
);
export default authrouter;
