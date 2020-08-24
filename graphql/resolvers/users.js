const { User } = require("../../models");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Op } = require("sequelize");
const { UserInputError, AuthenticationError } = require("apollo-server");

module.exports = {
  Query: {
    getUsers: async (parent, args, { user }) => {
      try {
        if (!user) {
          throw new AuthenticationError("Unauthenticated");
        }
        const users = await User.findAll({
          where: { username: { [Op.ne]: user.username } },
        });
        return users;
      } catch (err) {
        console.log(err);
        throw err;
      }
    },
    login: async (parent, args) => {
      const { username, password } = args;

      try {
        const user = await User.findOne({ where: { username } });
        let errors = {};
        if (username.trim() === "") {
          errors.username = "Username must not be empty";
        }
        if (password === "") {
          errors.password = "Password must not be empty";
        }

        if (Object.keys(errors).length > 0) {
          throw new UserInputError("Invalid input", { errors });
        }

        if (!user) {
          errors.username = "User not found";
          throw new UserInputError("user not found", { errors });
        }

        const correctPassword = await bcrypt.compare(password, user.password);

        if (!correctPassword) {
          errors.password = "Password is incorrect";
          throw new AuthenticationError("Password is incorrect", { errors });
        }

        const token = jwt.sign({ username }, "secretkey", { expiresIn: "1h" });

        return {
          ...user.toJSON(),
          createdAt: user.createdAt.toISOString(),
          token,
        };
      } catch (err) {
        console.log(err);
        throw err;
      }
    },
  },
  Mutation: {
    register: async (parent, args) => {
      let { username, email, password, confirmPassword } = args;
      let errors = {};
      try {
        //Validate Input Data
        if (email.trim() === "") {
          errors.email = "Email must not be empty";
        }
        if (username.trim() === "") {
          errors.username = "Username must not be empty";
        }
        if (password.trim() === "") {
          errors.password = "Password must not be empty";
        }
        if (confirmPassword.trim() === "") {
          errors.confirmPassword = "Confirm password must not be empty";
        }
        if (password !== confirmPassword) {
          errors.confirmPassword = "Passwords must match";
        }

        //If username/email exist?

        //const userByUsername = await User.findOne({ where: { username } });
        //const userByEmail = await User.findOne({ where: { email } });

        //if (userByUsername) {
        //errors.username = "Username is taken";
        //}
        //if (userByEmail) {
        //errors.email = "Email is taken";
        //}

        if (Object.keys(errors).length > 0) {
          throw errors;
        }

        // Hash password
        password = await bcrypt.hash(password, 6);

        //Create User
        const user = await User.create({
          username,
          email,
          password,
        });
        //Return User
        return user;
      } catch (err) {
        console.log(err);
        if (err.name === "SequelizeUniqueConstraintError") {
          err.errors.forEach(
            (e) => (errors[e.path] = `${e.path} already taken`)
          );
        } else if (err.name === "SequelizeValidationError") {
          err.errors.forEach((e) => (errors[e.path] = e.message));
        }
        throw new UserInputError("Bad input", { errors });
      }
    },
  },
};
