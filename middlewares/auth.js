import jwt from 'jsonwebtoken'

export const tokenVerify = (req,res, next) => {
    if(!req.headers.authorization){
        return res.status(403).send({error : 'no access token is present !!'})
    }

    const token = req.headers.authorization.split(" ")[1]

    jwt.verify(token,'my_secret', (err) => {
        if(err){
            return res.status(401).send({error: 'Invalid token !!'})
        }
        next()
    })
}

export const adminAuth = (req,res,next) => {
    const token = req.headers.authorization.split(" ")[1]
    const tokenDecoded =  jwt.decode(token)
  
    if(tokenDecoded.rol != '2'){
        return res.status(403).send({error : 'Forbidden'})
    }

    next()
} 

export const userAuth = (req,res,next) => {
    const token = req.headers.authorization.split(" ")[1]
    const tokenDecoded =  jwt.decode(token)
  
    if(tokenDecoded.rol != '1'){
        return res.status(403).send({error : 'Forbidden'})
    }

    next()
} 

