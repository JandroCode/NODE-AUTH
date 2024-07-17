import jwt from 'jsonwebtoken'

const SIGNATURE_KEY = 'my_secret'

export const generateToken = (payload) => {
    return jwt.sign(payload, SIGNATURE_KEY)
}

