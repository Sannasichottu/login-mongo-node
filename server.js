const express = require('express');
const path = require('path');
const app = express();
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
require ('dotenv').config();
const User = require('./model/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');



const JWT_SECRET = 'sdnxhjbxhbcnhjnjx@n*jknkuiee83bshjbjkn'

const uri = process.env.DB_URI
mongoose.set('strictQuery',false)
mongoose.connect(uri,err=>{
    if(err)throw err
})

const connection = mongoose.connection;

connection.once('open',()=>{
    console.log("Database connect successfully")
})



app.use('/',express.static(path.join(__dirname,'static')));
app.use(bodyParser.json());

app.post('/api/change-password', async(req,res) => {
    const { token, newpassword:plainTextPassword } = req.body;

    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json ({ status:'error', error:'Invalid password'})
    }

    if(plainTextPassword.length < 5) {
        return res.json({
            status: 'error',
            error : 'Password too small. Should be atleast 6 characters'
        })
    }

    try {
        const user = jwt.verify(token ,  JWT_SECRET);
        const _id = user.id

        const password = await bcrypt.hash(plainTextPassword, 10)
        await User.updateOne(
            { _id },
            {
                $set: {password}
            }
        )
        res.json({ status : 'ok' })
    } catch (error) {
        res.json({ status: 'error', error: ';))' })
    }


    res.json({ status : 'ok'})
})

app.post('/api/login',async (req,res)=> {

    const {username, password} = req.body;
    const user = await User.findOne({username}).lean()

    if (!user) {
        return res.json({ status:'error', error:'Invalid username/password'})
    }

    if(await bcrypt.compare(password, user.password)) {

        const token = jwt.sign({ id: user._id, username: user.username },JWT_SECRET)

        return res.json({ status:'ok', data:token})
    }



    res.json({ status: 'error', error:'Invalid username/password'})
});

app.post('/api/register',async (req,res)=> {
    console.log(req.body);

    const {username, password : plainTextPassword} = req.body;

    if(!username || typeof username !== 'string') {
        return res.json({ status: 'error', error:'Invalid username' })
    }

    if(!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({ status: 'error', error:'Invalid password' })
    }

    if (plainTextPassword.length < 5 ) {
        return res.json({ status: 'error', error:'Password too small. should be atleast 6 characters' })
    }

    const password = await bcrypt.hash(plainTextPassword, 10);

    try {
        const response = await User.create({
            username,
            password
        })
        console.log('User create successfull : ', response)
    } catch (error) {
        if (error.code === 11000) {
            return res.json({status:'error',  error:'Username already in use'})
        }
        throw error
    }

    res.json({status : 'ok'})
})

app.listen(process.env.PORT,()=> {
    console.log('Server running on port 3001');
})
