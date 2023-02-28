import joi from "@hapi/joi";

const schema = {
  user: joi.object({
    fullName: joi.string().max(100).required(),
    email: joi
      .string()
      .email({ minDomainSegments: 2, tlds: { allow: ["com", "in"] } }),
    password: joi
      .string()
      .pattern(new RegExp("^[a-zA-Z0-9]{3,30}$"))
      .required(),
    confirmPassword: joi
      .any()
      .equal(joi.ref("password"))
      .required()
      .label("Confirm password")
      .options({ messages: { "any.only": "{{#label}} does not match" } }),
  }),
};

export default schema;
