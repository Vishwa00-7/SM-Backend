
//Importing Modules

require('dotenv').config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { type } = require('node:os');
const passport = require("passport");
const GoogleStrategy = require('passport-google-oauth20').Strategy;



//Importing Sensitive data / secrets from .env

const PORT = process.env.PORT || 3000;
const DB_URL = process.env.DATABASE_URL;
const Refresh_Token_Secret = process.env.REFRESH_TOKEN_SECRET || process.env.Refresh_Token_Secret || "dev-refresh-secret";
const Access_Token_Secret = process.env.ACCESS_TOKEN_SECRET || process.env.Access_Token_Secret || "dev-access-secret";
const Google_Client_ID = process.env.GOOGLE_CLIENT_ID;
const Google_Client_Secret = process.env.GOOGLE_CLIENT_SECRET;



//Connecting with Mongoose

mongoose.connect(DB_URL)
    .then(() => { console.log("connected to mongodb"); })
    .catch(() => { console.log("Issue in mongodb"); });


//Creating Schema 

//userSchema -> contains info about users who created their account through (name and password)
//contains
//name , password
//dataID -> stores object id of userInfo (collection) , (Foreign Key)

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    password: { type: String, required: true },
    dataID: { type: mongoose.Schema.Types.ObjectId, required: true }
});

//googleUserSchema -> contains info about users who created their account through Google login
//contains
//email , username
//dataID -> stores object id of userInfo (collection) , (Foreign Key)

const googleUserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    dataID: { type: mongoose.Schema.Types.ObjectId, required: true }
});

//RefreshToken -> Stores RefreshToken and expiry Information
//contains 
//token -> RefreshToken itself
//will be add Later ---------------- !!!!!

const refreshTokenSchema = new mongoose.Schema({
    token: { type: String, required: true },
    expireAt: { type: Date, required: true }
});


//userInfoSchema -> Contains User Info, dataID will refer this collection

//contains
//amount ,  name , portfolio , transaction , watchlist

//Array of Objects
//Watchlist   -> [{StockSymbol , StockName}]
//portfolio   -> [id , symbol , stockname , price , date and time (in ms)]
//transaction -> [id , symbol , stockname , Costprice , date and time @purchase, sellingprice , date and time @selling]

const userInfoSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 0
    },
    watchlist: {
        type: [[mongoose.Schema.Types.Mixed]],
        default: [],
        required: true
    },
    portfolio: {
        type: [[mongoose.Schema.Types.Mixed]],
        default: [],
        required: true
    },
    transaction: {
        type: [[mongoose.Schema.Types.Mixed]],
        default: [],
        required: true
    }
});


//creating model
const User = mongoose.model("user", userSchema);
const GoogleUser = mongoose.model("googleuser", googleUserSchema);
const RefreshTokenDB = mongoose.model("refreshtoken", refreshTokenSchema);
const UserInfo = mongoose.model("userinfo", userInfoSchema);


//using express
const app = express();

//using Middleware on express
app.use(express.json());
app.use(cors({
    origin: "http://localhost:5173", // Your React App URL
    credentials: true                // Allows cookies to be sent
}));
app.use(cookieParser());


//Functions for API

//Fetching from database
async function getUserByName(username) {
    try {
        let result = await User.findOne({ name: username });
        return result;
    }
    catch (e) {
        return null;
    }
}

async function getGoogleUserByEmail(email) {
    try {
        let result = await GoogleUser.findOne({ email: email });
        return result;
    }
    catch (e) {
        return null;
    }
}

async function addRefreshTokenToDB(token) {
    try {
        const refreshToken = await RefreshTokenDB.create({
            token: token,
            expireAt: Date.now() + (30 * 24 * 3600 * 1000)
        });
        return true;
    }
    catch (e) {
        return false;
    }
}

async function checkRefreshTokenInDB(token) {
    try {
        let result = await RefreshTokenDB.findOne({ token: token });
        if (result != null) {
            if (result.expireAt < Date.now())
                return true;
            else    //remove the expired Token
                RefreshTokenDB.deleteOne({ token: token });
        }
        return false;
    }
    catch (e) {
        return false;
    }
}

async function clearRefreshTokenInDB(token) {
    try{
        let flag = RefreshTokenDB.deleteOne({ token: token });
        return true;
    }
    catch(e){
        return false;
    }
}

async function getUserInfoById(id) {
    try {
        let result = await UserInfo.findById(id);
        return result;
    }
    catch (e) {
        return null
    }
}

async function updateUserInfoById(id, info) {
    try {
        const updatedResult = await UserInfo.findByIdAndUpdate(id,
            { $set: info },
            { new: true, runValidators: true }
        );
        return true;
    }
    catch (e) {
        return false;
    }
}


//Creating Refresh Token and Access Token

function generateRefreshToken(payload) {
    const refreshToken = jwt.sign(payload, Refresh_Token_Secret, { expiresIn: "30d" });
    return refreshToken;
}

function generateAccessToken(payload) {
    const accessToken = jwt.sign(payload, Access_Token_Secret, { expiresIn: "15m" });
    return accessToken;
}

//Authenticate accessToken before fetching from database (Middleware for JWT)
function authenticateToken(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) return res.status(401).json({ message: 'Access token missing' });

        const Decoded_Payload = jwt.verify(token, Access_Token_Secret);
        req.ID = Decoded_Payload.ID;
        next();
    }
    catch (err) {
        if (err.name === 'TokenExpiredError')
            res.status(403).json({ message: 'The token has expired!' });
        else if (err.name === 'JsonWebTokenError')
            res.status(403).json({ message: 'The token is invalid' });
        else
            res.status(403).json({ message: 'Some other token error occurred.' });
    }
}


//PassPort Configuration (Middleware for Google authentication)

passport.use(new GoogleStrategy({
    clientID: Google_Client_ID,
    clientSecret: Google_Client_Secret,
    callbackURL: 'https://sm-backend-qjvf.onrender.com/auth/google/callback'
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            let googleUser = {
                googleId: profile.id,
                name: profile.displayName,
                email: profile.emails[0].value,
                newAccount: true
            };        //Get Details From google (like name email..)

            const result = await getGoogleUserByEmail(googleUser.email);
            if (result != null)
                googleUser.newAccount = false;

            done(null, googleUser);    //similar to next in middleware but it will pass 
            //req.user = googleUser or null (first parameter) (if there are any errors)

        }
        catch (e) {
            return done(e);
        }
    }
));

//Creating API



//status code
// 200 - 299 -> success (200 -> ok , 201 -> created / updated)
// 300 - 399 -> success (but using older version -> Not Needed )
// 400 - 499 -> Your fault (401 -> missing , 402 invalid name or password ,
//                          403 -> expired , 404 -> Account did n't found)
// 500 -> server / backend fault -> displayErrorBlock


//checkToken , readUserInfo and updateUserInfo -> returns json
//remaining returns text

app.post("/signin", async (req, res) => {
    try {
        let request = req.body;
        const accountInfo = await getUserByName(request.name);
        if (accountInfo != null) {
            res.statusCode = 402;
            res.send("Name Already Exist");
        }
        else {
            const newUserInfo = await UserInfo.create({ name: request.name, amount: 20000 });
            const ID = newUserInfo.id;
            // console.log(ID);
            const hashed_password = await bcrypt.hash(request.password, 10);
            const newAccountInfo = await User.create({
                name: request.name,
                password: hashed_password,
                dataID: ID
            });
            res.statusCode = 201;
            res.send("Account Created Successfully");
        }

    }
    catch (e) {
        // console.log(e.message);
        res.statusCode = (500);
        res.send(e.message);
    }
});


app.post("/login/input", async (req, res) => {
    try {
        let request = req.body;
        const accountInfo = await getUserByName(request.name);
        if (accountInfo != null) {

            const hashed_password = accountInfo.password;
            const input_password = request.password;

            if (bcrypt.compareSync(input_password, hashed_password)) {
                //Return JWT ( both refresh token and access token )
                const payload = { ID: accountInfo.dataID };
                const refreshToken = generateRefreshToken(payload);
                addRefreshTokenToDB(refreshToken);
                // console.log("RefreshToken", refreshToken); //--------------------
                res.cookie("RefreshToken", refreshToken, {
                    httpOnly: true,
                    secure: true, //change it to True at https --------  !!!!!!!!!
                    sameSite: "strict",
                    maxAge: 30 * 24 * 60 * 60 * 1000
                });

                const accessToken = generateAccessToken(payload);
                res.status(200).send(accessToken);
            }
            else {
                res.statusCode = 402;
                res.send("Invalid Password");
            }
        }
        else {
            res.statusCode = 404;
            res.send("Account Did n't Exist");
        }

    }
    catch (e) {
        // console.log(e.message);
        res.statusCode = (500);
        res.send(e.message);
    }
});

//Check Wether the accessToken is Expired or Not
app.get("/checktoken", authenticateToken, async (req, res) => {
    try {
        res.statusCode = 200;
        res.json({ message: "The token is Valid" });
    }
    catch (e) {
        // console.log(e.message);
        res.statusCode = (500);
        res.json({ message: "Some Error Occured" });
    }
});

//Generate Access Token using Refresh Token ...... ---------   !!!!!!!
app.get("/generatetoken", async (req, res) => {
    try {
        const refreshToken = req.cookies.RefreshToken;
        if (!refreshToken)
            return res.status(401).send("Refresh Token is Missing");
        if (!checkRefreshTokenInDB(refreshToken))
            return res.status(401).send("Refresh Token is Expired");
        const Decoded_Payload = jwt.verify(refreshToken, Refresh_Token_Secret);
        // console.log("decode payload ", Decoded_Payload);
        const accessToken = generateAccessToken({ ID: Decoded_Payload.ID });
        res.status(200).send(accessToken);

    }
    catch (e) {
        // console.log(e.message);
        res.statusCode = (500);
        res.send("Some Error Occured" + e.message);
    }
});

//GOOGLE AUTHENTICATION
// Step 1: Redirect user to Google Login screen
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'], session: false })
);

// Step 2: Google sends user back here with credentials
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/', session: false }), async (req, res) => {
    try {
        const user = req.user;
        let ID = null;
        if (user.newAccount == true) {
            //Creating User Info
            const newUserInfo = await UserInfo.create({ name: user.name, amount: 20000 });
            ID = newUserInfo.id;

            //Creating Account Info
            const newAccountInfo = await GoogleUser.create({
                name: user.name,
                email: user.email,
                dataID: ID
            });
        }
        else {
            const result = await getGoogleUserByEmail(user.email);
            ID = result.dataID;
        }

        const payload = { ID: ID };
        const refreshToken = generateRefreshToken(payload);
        addRefreshTokenToDB(refreshToken); 
        // console.log("RefreshToken", refreshToken); //--------------------
        res.cookie("RefreshToken", refreshToken, {
            httpOnly: true,
            secure: true, //change it to True at https --------  !!!!!!!!!
            sameSite: "strict",
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        const accessToken = generateAccessToken(payload);
        //res.status(200).send(accessToken);
        res.redirect(`http://localhost:5173?token=${accessToken}`);

    }
    catch (e) {
        // console.log(e.message);
        res.statusCode = (500);
        res.send( e.message);
    }
});

app.get("/logout" , (req,res)=>{
    try{
        // console.log("started")
        const flag = clearRefreshTokenInDB(req.cookies.RefreshToken);
        res.cookie('RefreshToken', '', {
        httpOnly: true,
        maxAge : 0,
        secure: true,
        sameSite: 'strict'
    });
        // console.log(flag)
        res.status(200).send("Logged Out Successfully")
    }
    catch(e){
        // console.log(e);
        res.status(500).send(e.message);
    }
});




//Read UserInfo
app.get("/userinfo", authenticateToken, async (req, res) => {
    try {
        let ID = req.ID;
        let info = await getUserInfoById(ID);
        if (info == false)
            throw new Error("cant fetch from DB");
        res.status(200).json(info)
    }
    catch (e) {
        // console.log(e.message);
        res.statusCode = (500);
        res.json({ message: "Some Error Occured" });
    }
});

//Update UserInfo
app.put("/userinfo", authenticateToken, async (req, res) => {
    try {
        let ID = req.ID;
        let updatedInfo = req.body;
        let flag = await updateUserInfoById(ID, updatedInfo);
        if (flag == false)
            throw new Error("cant fetch fom DB");
        res.status(201).json({ message: "Updated Successfully" })
    }
    catch (e) {
        // console.log(e.message);
        res.statusCode = (500);
        res.json({ message: "Some Error Occured" });
    }
});



/*
app.METHOD("/ENDPOINT" , async (req,res) => {
    try{
        let request = req.body;
    }
    catch(e){
        // console.log(e.message);
        res.statusCode = (500);
        res.send("Some Error Occured");
    }
} );
 */


app.listen(PORT, () => {
    // console.log("Server is Listening...");
});