import express from "express";
import Auth from "../models/authM.js";
import bcrypt from "bcrypt";
import Jwt from "jsonwebtoken";
import randomstring from "randomstring";
import moment from "moment";
import checkauth from "../middleware/authT.js";
import adminauth from "../middleware/adminT.js";
import multer from "multer";
import fileUpload from "express-fileupload";
import { v2 as cloudinary } from "cloudinary";
import { url } from "inspector";
import dotenv from "dotenv";
import adduservali from "../validation/authValidation.js";

const adminrouter = express.Router();

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
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
    file.mimetype === "image/jpeg"
  ) {
    cb(null, true);
  } else {
    cb(null, false);
  }
};
const upload = multer({ storage: storage, fileFilter: filefilter });

//ADMIN LOGIN.....................................................................................
adminrouter.post("/admin/login", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const userdata = await Auth.findOne({ email: email });

  if (userdata) {
    const passwordmatch = await bcrypt.compare(password, userdata.password);

    if (passwordmatch) {
      if (userdata.isAdmin === false) {
        res.status(400).send({ error: "you are not admin" });
      } else if (userdata.isVarified === 0) {
        res.status(400).send({ error: "you block by super admin" });
      } else {
        const checkpassword = await bcrypt.compare(
          req.body.password,
          userdata.password
        );

        const token = await userdata.generateTokens();

        // console.log(token);

        const date = moment().format("L");

        let Id = userdata._id;

        res
          .status(200)
          .send({ success: "😉welcome admin..!!", token, Id, date });
      }
    } else {
      res.status(400).send({ error: "please try again" });
    }
  } else {
    res.status(401).send({ error: "please try again" });
  }
});

//REGISTER ADMIN DETAILS FIND HELP OF TOKEN
adminrouter.get("/adminProfile", [checkauth, adminauth], async (req, res) => {
  try {
    const user = await Auth.find({ _id: req.user._id });

    if (user) {
      const data = {
        _id: req.user._id,
        fullName: req.user.fullName,
        email: req.user.email,
        image: req.user.image,
      };
      res.status(200).send({ success: "Admin Details....", data });
    } else {
      res.status(400).send({ error: "not found admin detail" });
    }
  } catch (err) {
    res.status(400).send({ error: "user not found please try again" });
  }
});

//UPDATE ADMIN DETAILS................................
adminrouter.put(
  "/updateAdmin/:id",
  [checkauth, adminauth],
  async (req, res) => {
    try {
      const file = req.files.image;
      let user = await Auth.findById(req.params.id);
      const dis = await cloudinary.uploader.destroy(file.tempFilePath);

      let result;
      if (dis) {
        result = await cloudinary.uploader.upload(file.tempFilePath);
      }
      const data = {
        fullName: req.body.fullName || user.fullName,
        email: req.body.email || user.email,
        image: result?.secure_url || user.image,
        cloudinary_id: result?.public_id || user.cloudinary_id,
      };
      user = await Auth.findByIdAndUpdate(req.params.id, data, { new: true });
      res.status(200).send(user);
    } catch (err) {
      console.log("err");
    }
  }
);

//GET THE ADMIN DETAILS WITHOUT TOKEN...................................................
adminrouter.get("/getadminProfile", async (req, res) => {
  try {
    const user = await Auth.find({});
    if (user) {
      const data = user.filter((item) => item.isAdmin == true);

      if (data.length <= 0) {
        return res.status(400).send({ message: "admin not found" });
      } else if (data.length >= 0) {
        const email = data.map((item) => item.email); //only show email

        return res.status(200).send({ message: "get admin profile", email });
      }
    } else {
      return res.status(400).send({ message: "admin not found" });
    }
  } catch (err) {
    res.status(400).send({ message: "something wrong..." });
  }
});

//GET ALL REGISTER USER................................
adminrouter.get("/allUser", [checkauth, adminauth], async (req, res) => {
  try {
    const user = await Auth.find({});
    if (user) {
      const data = user.filter((item) => item.isAdmin == false);

      if (data.length <= 0) {
        return res
          .status(400)
          .send({ status: "Bad Request", data: "", message: "user not found" });
      } else if (data.length >= 0) {
        return res.status(200).send({ status: "success", details: data });
      }
    } else {
      return res
        .status(400)
        .send({ status: "Bad Request", data: "", message: "user not found" });
    }
  } catch (err) {
    res
      .status(400)
      .send({ status: "Bad Request", data: "", message: "something wrong..." });
  }
});
export default adminrouter;
