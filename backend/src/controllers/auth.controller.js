
import User from '../models/user.model.js';
import { generateToken } from '../lib/utils.js';
import bcrypt from 'bcryptjs';

export const signup = async (req,res) => {
    const { email, fullName, password } = req.body;
    try {
        //validate user input or check if all fields are filled
        if (!email || !fullName || !password) {
            return res.status(400).json({ message: "All fields are required" }); //return error if any field is empty
        }
        //validate password or check the length of password
        if (password.length < 6 ){
            return res.status(400).json( { message : " Password must be at least 6 characters !! " } ); //error if password is less than 6 characters
        }
        //check if user already exists
        const user = await User.findOne({ email });
        if (user) return res.status(400).json({ message: "User already exists !" });

        //hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        //if user doesn't exist and password is hashed then create new user
        const newUser = new User({
            fullName,
            email,
            password: hashedPassword
        })

        if (newUser) {
            //generate jws token here
            generateToken(newUser._id, res);
            await newUser.save();

            res.status(201).json({ 
                _id: newUser._id,
                fullName: newUser.fullName,
                email: newUser.email,
                profilePic: newUser.profilePic,
            })
        } else {
            res.status(400).json({ message : " Invalid user data !! " });
        }


    } catch (error) {
        console.log("Error in signup controller :" , error.message);
        res.status(500).json({ message: "Server error" });
    }
}

export const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        //validate user input or check if all fields are filled 
        if (!email || !password) {
            return res.status(400).json({ message: "All fields are required" }); //return error if any field is empty
        }
        //check if user exists
        const user = await User.findOne({email});

        if (!user) {
            return res.status(404).json({ message: "Invalid Credentials" });
        }

        //check if password is correct
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }

        generateToken(user._id, res); //generate jws token here

        res.status(200).json({
            _id: user._id,
            fullName: user.fullName,
            email: user.email,
            profilePic: user.profilePic,
        })

    } catch (error) {
        console.log("Error login in controller :", error.message);
        res.status(500).json({ message: "Internal Server error" });
    }
}

export const logout = (req,res) => {
    try {
        res.cookie("jwk", "" , {maxAge: 0}); // Clear the cookie by setting maxAge to 0
        res.status(200).json({ message: "Logged out successfully !!" });
    } catch (error) {
        console.log("Error in logout controller :", error.message);
        res.status(500).json({ message: "Internal Server error" });
    }
}