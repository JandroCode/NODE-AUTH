import express, { json } from 'express'
import cors from 'cors'
import { conn } from './db.js'
import bcrypt from 'bcrypt'
import { generateToken }  from './services/token.service.js'
import { tokenVerify , adminAuth, userAuth } from './middlewares/auth.js'


const app = express()

app.use(json())
app.use(cors())


app.post('/api/register' , async(req,res) => {
    const { username, password, email } = req.body
    const passwordHash = await bcrypt.hash(password,10)
 
    if(!username || !email || !password) {
        res.status(400).send({error : 'Los campos son obligatorios'})
        return
    } 
        
    const [result] = await conn.query("INSERT INTO usuarios(username,password,email, rol_id) VALUES(?,?,?,?)", [username, passwordHash,email, 1])

    const response = {
        id : result.insertId,
        username : req.username,
        email : req.email,
    }

    if(result.insertId > 0){
        res.status(201).send(response)
    }else{
        res.status(500).send({
            error : 'Internal Server Error !'
        })
    }
})

app.post('/api/login' , async(req,res) => {
    const { username, password } = req.body

    if(!username || !password) {
        res.status(400).send({error : 'Los campos son obligatorios'})
        return
    } 
        
    const [result] = await conn.query("SELECT * FROM usuarios WHERE username = ?" , [username])

    if(result.length == 0){
        res.status(401).send({error : 'No autorizado !'})
        return
    }
    
    if(result.length >0){
        const userValid = await bcrypt.compare(password, result[0].password)
        const payload = {
            username : result[0].username,
            rol : result[0].rol_id
        }

    
        
        if(userValid){
            const token = generateToken(payload)
            res.status(200).send({token : token})
            return
        }else{
            res.status(401).send({error : 'No autorizado !'})
            return
        }
    }
})

app.get('/api/admin' , tokenVerify, adminAuth, async(req,res) => {
    res.send({message : 'Hello admin !'})
})

app.get('/api/user' , tokenVerify, userAuth, async(req,res) => {
    res.send({message : 'Hello user !'})
})




app.listen(3000)
