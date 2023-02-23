import mongoose from "mongoose";
var Schema = mongoose.Schema;
import jwt from "jsonwebtoken";

const authSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
    },
    email: {
      type: String,
    },
    password: {
      type: String,
    },
    confirmPassword: {
      type: String,
    },
    image : {
      type: String,
    },
    isAdmin :{
      type : Boolean,
      default : false,
    },
    isVarified:{
      type: Number,
      default: 0
    }
  },
  { versionKey: false }
);

authSchema.methods.generateTokens = async function () {
  const token = jwt.sign(
    { _id: this._id, isAdmin: this.isAdmin },
    "privatekey",
    {
      expiresIn: "24h",
    }
  );
  return token;
};

const Auth = mongoose.model("eLerningPlateform", authSchema);

export default Auth;
