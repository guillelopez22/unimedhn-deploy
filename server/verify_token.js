var jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
    console.log(req.headers);
    if(req.headers['authorization']){
        var token = req.headers['authorization'].replace("Bearer ","");
        if (!token)
            return res.status(403).send({auth: false, title:"Acceso No Autorizado", message:"Intento acceder a un recurso prohibido"});
        jwt.verify(token, process.env.TOKEN_SECRET_KEY, function(err, decoded) {
            if (err){
                return res.status(403).send({auth: false, title:"Acceso No Autorizado", message:"Intento acceder a un recurso prohibido"});
            }
            req.user_id = decoded.id;
            next();
        });
    }else{
        return res.status(403).send({auth: false, title:"Acceso No Autorizado", message:"Intento acceder a un recurso prohibido"});
    }
    
}

module.exports = verifyToken;