const express = require('express');
const router = express.Router();
var mysql = require('mysql');
const fs = require("fs");
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
const nodemailer = require("nodemailer");
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
const verify_token = require("./verify_token");

let transporter = nodemailer.createTransport({
    host: "smtp.office365.com",
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

var con = mysql.createPool({
    connectionLimit: 100,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_SCHEMA,
    insecureAuth: true,
    multipleStatements: true
});

//########################################################################
//AUTH ###################################################################
router.get('/login', (req, res, next) => {
    var select_username_query = "" +
        " SELECT id" +
        " FROM users" +
        " WHERE" +
        " username = ?";
    var select_username_values = [
        req.query.username
    ];
    con.query(select_username_query, select_username_values, function (select_username_err, select_username_result, select_username_fields) {
        if (select_username_err) {
            next(select_username_err);
        } else {
            if (select_username_result.length > 0) {
                var validate_user_password_query = "" +
                    " SELECT id, username, role, user_email, first_login" +
                    " FROM users" +
                    " WHERE" +
                    " username = ?" +
                    " AND password = SHA(?)" +
                    " AND active = 1";
                var validate_user_password_values = [
                    req.query.username,
                    req.query.password
                ];
                con.query(validate_user_password_query, validate_user_password_values, function (validate_user_password_err, validate_user_password_result, validate_user_password_fields) {
                    if (validate_user_password_err) {
                        next(validate_user_password_err);
                    } else {
                        if (validate_user_password_result.length > 0) {
                            if (validate_user_password_result[0].first_login == 1) {
                                res.status(200).json({
                                    auth: true,
                                    first_login: true,
                                    id: encrypt(validate_user_password_result[0].id + ""),
                                    name: validate_user_password_result[0].username
                                });
                            } else {
                                var token = jwt.sign({
                                    id: validate_user_password_result[0].id,
                                    role: validate_user_password_result[0].role
                                },
                                    process.env.TOKEN_SECRET_KEY,
                                    {
                                        expiresIn: 86400
                                    });
                                res.status(200).json({
                                    auth: true,
                                    first_login: false,
                                    token: token,
                                    name: validate_user_password_result[0].username
                                });
                            }
                        } else {
                            res.status(400).json({
                                auth: false,
                                title: "Error de Autenticación",
                                message: 'Combinación de usuario y contraseña incorrectos'
                            });
                        }
                    }
                });
            } else {
                res.status(400).json({
                    auth: false,
                    title: "Error de Autenticación",
                    message: 'El usuario con el cual está intentando acceder no existe'
                });
            }
        }
    });
});

router.get('/login', (req, res, next) => {
    var select_username_query = "" +
        " SELECT id" +
        " FROM users" +
        " WHERE" +
        " username = ?";
    var select_username_values = [
        req.query.username
    ];
    con.query(select_username_query, select_username_values, function (select_username_err, select_username_result, select_username_fields) {
        if (select_username_err) {
            next(select_username_err);
        } else {
            if (select_username_result.length > 0) {
                var validate_user_password_query = "" +
                    " SELECT id, role, username, first_login" +
                    " FROM users" +
                    " WHERE" +
                    " username = ?" +
                    " AND password = SHA(?)" +
                    " AND active = 1";
                var validate_user_password_values = [
                    req.query.username,
                    req.query.password
                ];
                con.query(validate_user_password_query, validate_user_password_values, function (validate_user_password_err, validate_user_password_result, validate_user_password_fields) {
                    if (validate_user_password_err) {
                        next(validate_user_password_err);
                    } else {
                        if (validate_user_password_result.length > 0) {
                            if (validate_user_password_result[0].first_login == 1) {
                                res.status(200).json({
                                    auth: true,
                                    first_login: true,
                                    id: encrypt(validate_user_password_result[0].id + ""),
                                    name: validate_user_password_result[0].username
                                });
                            } else {
                                res.status(200).json({
                                    auth: true,
                                    first_login: false,
                                    id: encrypt(validate_user_password_result[0].id + ""),
                                    name: validate_user_password_result[0].username
                                });
                            }
                        } else {
                            res.status(400).json({
                                auth: false,
                                title: "Error de Autenticación",
                                message: 'Combinación de usuario y contraseña incorrectos'
                            });
                        }
                    }
                });
            } else {
                res.status(400).json({
                    auth: false,
                    title: "Error de Autenticación",
                    message: 'El usuario con el cual está intentando acceder no existe'
                });
            }
        }
    });
});

router.post('/request_recovery_code', (req, res, next) => {
    var select_user_email_query = "" +
        " SELECT id, username FROM" +
        " users" +
        " WHERE" +
        " user_email = ?";
    var select_user_email_values = [
        req.body.user_email
    ];
    con.query(select_user_email_query, select_user_email_values, function (select_user_email_err, select_user_email_result, select_user_email_fields) {
        if (select_user_email_err) {
            next(select_user_email_err);
        } else {
            if (select_user_email_result.length > 0) {
                var code = generate_recovery_code(5);
                try {
                    transporter.sendMail({
                        from: '"UNIMED"',
                        to: req.body.user_email,
                        subject: "Código de Recuperación",
                        html: "Estimado/a " + select_user_email_result[0].username + ":<br><br>El código para recuperar su usuario o contraseña es el siguiente: <b>" + code + "</b><br>Ingrese el código proporcionado en el formulario de recuperación de credenciales."
                    });
                } catch (mailer_error) {
                    console.log(mailer_error);
                }
                var assign_code_query = "" +
                    " UPDATE users" +
                    " SET" +
                    " restore_code = ?" +
                    " WHERE" +
                    " id = ?";
                var assign_code_values = [
                    code,
                    select_user_email_result[0].id
                ];
                con.query(assign_code_query, assign_code_values, function (assign_code_err, assign_code_result, assign_code_fields) {
                    if (assign_code_err) {
                        next(assign_code_err);
                    } else {
                        res.status(200).json({
                            id: encrypt(select_user_email_result[0].id + ""),
                            title: "Código de Recuperación Generado",
                            message: 'El código de recuperación se generó y envió a su correo de forma satisfactoria'
                        });
                    }
                });
            } else {
                res.status(400).json({
                    title: "Error",
                    message: 'El correo electrónico proporcionado no se encuentra asociado a un usuario dentro del sistema'
                });
            }
        }
    });
});

router.get('/validate_recovery_code', (req, res, next) => {
    var validate_user_code_query = "" +
        " SELECT id, username FROM" +
        " users" +
        " WHERE" +
        " id = ?" +
        " AND user_email = ?" +
        " AND restore_code = ?";
    var validate_user_code_values = [
        decrypt(req.query.id),
        req.query.user_email,
        req.query.restore_code
    ];
    con.query(validate_user_code_query, validate_user_code_values, function (validate_user_code_err, validate_user_code_result, validate_user_code_fields) {
        if (validate_user_code_err) {
            next(validate_user_code_err);
        } else {
            if (validate_user_code_result.length > 0) {
                res.status(200).json({
                    id: encrypt(validate_user_code_result[0].id + ""),
                    title: "Código de Recuperación Válido",
                    message: 'El código de recuperación se validó correctamente'
                });
            } else {
                res.status(400).json({
                    title: "Error",
                    message: 'El código de recuperación no es válido'
                });
            }
        }
    });
});

router.post('/request_password_change', (req, res, next) => {
    var select_user_query = "" +
        " SELECT username,password  FROM" +
        " users" +
        " WHERE" +
        " id = ?" +
        " AND user_email = ?" +
        " AND restore_code = ?";
    var select_user_values = [
        decrypt(req.body.id),
        req.body.user_email,
        req.body.restore_code
    ];
    con.query(select_user_query, select_user_values, function (select_user_err, select_user_result, select_user_fields) {
        if (select_user_err) {
            next(select_user_err);
        } else {
            if (select_user_result.length > 0) {
                if (select_user_result[0].password != req.body.password) {
                    if (req.body.password.match(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,25}$/)) {
                        var update_password_query = "" +
                            " UPDATE" +
                            " users" +
                            " SET" +
                            " password = SHA(?)," +
                            " restore_code = ''" +
                            " WHERE" +
                            " id = ?" +
                            " AND user_email = ?" +
                            " AND restore_code = ?";
                        var update_password_values = [
                            req.body.password,
                            decrypt(req.body.id),
                            req.body.user_email,
                            req.body.restore_code
                        ];
                        con.query(update_password_query, update_password_values, function (update_password_err, update_password_result, update_password_fields) {
                            if (update_password_err) {
                                next(update_password_err);
                            } else {
                                res.status(200).json({
                                    valid: true,
                                    title: "Contraseña Cambiada Exitosamente",
                                    message: 'La contraseña se ha cambiado de forma satisfactoria'
                                });
                            }
                        });
                    } else {
                        res.status(400).json({
                            valid: false,
                            title: "Error",
                            message: 'La contraseña no posee los requisitos establecidos por el sistema'
                        });
                    }
                } else {
                    res.status(400).json({
                        valid: false,
                        title: "Error",
                        message: 'La contraseña proporcionada es la misma que posee el usuario actualmente'
                    });
                }
            } else {
                res.status(400).json({
                    valid: false,
                    title: "Error",
                    message: 'La contraseña no puede ser cambiada, favor contacte a un administrador de sistema'
                });
            }
        }
    });
});

router.post('/request_password_change_first_login', (req, res, next) => {
    var select_user_query = "" +
        " SELECT username, password FROM" +
        " users" +
        " WHERE" +
        " id = ?" +
        " AND first_login = 1";
    var select_user_values = [
        decrypt(req.body.id)
    ];
    con.query(select_user_query, select_user_values, function (select_user_err, select_user_result, select_user_fields) {
        if (select_user_err) {
            next(select_user_err);
        } else {
            if (select_user_result.length > 0) {
                if (select_user_result[0].password != req.body.password) {
                    if (req.body.password.match(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,25}$/)) {
                        var update_password_query = "" +
                            " UPDATE" +
                            " users" +
                            " SET" +
                            " password = SHA(?)," +
                            " restore_code = -1," +
                            " first_login = 0" +
                            " WHERE" +
                            " id = ?";
                        var update_password_values = [
                            req.body.password,
                            decrypt(req.body.id)
                        ];
                        con.query(update_password_query, update_password_values, function (update_password_err, update_password_result, update_password_fields) {
                            if (update_password_err) {
                                next(update_password_err);
                            } else {
                                res.status(200).json({
                                    valid: true,
                                    title: "Contraseña Cambiada Exitosamente",
                                    message: 'La contraseña se ha cambiado de forma satisfactoria'
                                });
                            }
                        });
                    } else {
                        res.status(400).json({
                            valid: false,
                            title: "Error",
                            message: 'La contraseña no posee los requisitos establecidos por el sistema'
                        });
                    }
                } else {
                    res.status(400).json({
                        valid: false,
                        title: "Error",
                        message: 'La contraseña proporcionada es la misma que posee el usuario actualmente'
                    });
                }
            } else {
                res.status(400).json({
                    valid: false,
                    title: "Error",
                    message: 'La contraseña no puede ser cambiada, favor contacte a un administrador de sistema'
                });
            }
        }
    });
});

//AUTH ###################################################################
//########################################################################

//########################################################################
//INSTITUCIONES ##########################################################
router.get('/get_institutions', verify_token, (req, res, next) => {
    let query_string = "";
    query_string = query_string + " SELECT * FROM instituciones";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
})

router.get('/get_instituciones', verify_token, (req, res, next) => {
    var count_values = [];
    var count_query = "" +
        " SELECT COUNT(id) as total FROM" +
        " instituciones" +
        " WHERE" +
        " nombre != ''";
    if (req.query.nombre) {
        count_query = count_query + " AND nombre LIKE " + con.escape('%' + req.query.nombre + '%');
    }
    if (req.query.departamento) {
        count_query = count_query + " AND departamento = ?";
        count_values.push(req.query.departamento);
    }
    if (req.query.ciudad) {
        count_query = count_query + " AND ciudad = ?";
        count_values.push(req.query.ciudad);
    }
    if (req.query.calendario) {
        count_query = count_query + " AND calendario = ?";
        count_values.push(req.query.calendario);
    }
    if (req.query.tipo) {
        count_query = count_query + " AND tipo = ?";
        count_values.push(req.query.tipo);
    }
    con.query(count_query, count_values, function (count_err, count_results, count_fields) {
        if (count_err) {
            next(count_err);
        } else {
            var query = ""
            var values = [];
            if (req.query.sort_order) {
                var asc = '';
                if (req.query.sort_ascendent == 'true') {
                    var asc = ' ORDER BY ' + req.query.sort_order + ' ASC';
                } else {
                    var asc = ' ORDER BY ' + req.query.sort_order + ' DESC';
                }
                query = "" +
                    " SELECT * FROM" +
                    " instituciones" +
                    " WHERE" +
                    " nombre != ''";
                if (req.query.nombre) {
                    query = query + " AND nombre LIKE " + con.escape('%' + req.query.nombre + '%');
                }
                if (req.query.departamento) {
                    query = query + " AND departamento = ?";
                    values.push(req.query.departamento);
                }
                if (req.query.ciudad) {
                    query = query + " AND ciudad = ?";
                    values.push(req.query.ciudad);
                }
                if (req.query.calendario) {
                    query = query + " AND calendario = ?";
                    values.push(req.query.calendario);
                }
                if (req.query.tipo) {
                    query = query + " AND tipo = ?";
                    values.push(req.query.tipo);
                }
                query = query + asc + " LIMIT ?, ?";
                values.push(parseInt(req.query.current_offset));
                values.push(parseInt(req.query.view_length));
            } else {
                query = "" +
                    " SELECT * FROM" +
                    " instituciones" +
                    " WHERE" +
                    " nombre != ''";
                if (req.query.nombre) {
                    query = query + " AND nombre LIKE " + con.escape('%' + req.query.nombre + '%');
                }
                if (req.query.departamento) {
                    query = query + " AND departamento = ?";
                    values.push(req.query.departamento);
                }
                if (req.query.ciudad) {
                    query = query + " AND ciudad = ?";
                    values.push(req.query.ciudad);
                }
                if (req.query.calendario) {
                    query = query + " AND calendario = ?";
                    values.push(req.query.calendario);
                }
                if (req.query.tipo) {
                    query = query + " AND tipo = ?";
                    values.push(req.query.tipo);
                }
                query = query + " LIMIT ?, ?";
                values.push(parseInt(req.query.current_offset));
                values.push(parseInt(req.query.view_length));
            }
            con.query(query, values, function (err, results, fields) {
                if (err) {
                    next(err);
                } else {
                    res.status(200).json({ list: results, count: count_results[0].total });
                }
            });
        }
    });
});

router.post('/insert_institucion', verify_token, (req, res, next) => {
    var query = "" +
        " INSERT INTO instituciones" +
        " (" +
        " nombre," +
        " correo," +
        " telefono," +
        " departamento," +
        " ciudad," +
        " direccion," +
        " inicio_clases," +
        " calendario," +
        " tipo," +
        " contactos" +
        " )" +
        " VALUES" +
        " (" +
        " ?," +
        " ?," +
        " ?," +
        " ?," +
        " ?," +
        " ?," +
        " ?," +
        " ?," +
        " ?," +
        " ?" +
        " )";
    var values = [
        req.body.nombre,
        req.body.correo,
        req.body.telefono,
        req.body.departamento,
        req.body.ciudad,
        req.body.direccion,
        req.body.inicio_clases,
        req.body.calendario,
        req.body.tipo,
        req.body.contactos
    ];
    con.query(query, values, function (err, results, fields) {
        if (err) {
            next(err);
        } else {
            res.status(200).json({
                title: "Institución Creada Exitosamente",
                message: 'La institución se ha creado de forma satisfactoria'
            });
        }
    });
});

router.put('/update_institucion', verify_token, (req, res, next) => {
    console.log(req.body)
    var query = "" +
        " UPDATE instituciones" +
        " SET nombre = ?," +
        " correo = ?," +
        " telefono = ?," +
        " departamento = ?," +
        " ciudad = ?," +
        " direccion = ?," +
        " inicio_clases = ?," +
        " calendario = ?," +
        " tipo = ?," +
        " contactos = ?" +
        " WHERE id = ?";
    var values = [
        req.body.nombre,
        req.body.correo,
        req.body.telefono,
        req.body.departamento,
        req.body.ciudad,
        req.body.direccion,
        req.body.inicio_clases,
        req.body.calendario,
        req.body.tipo,
        req.body.contactos,
        req.body.id
    ];
    con.query(query, values, function (err, results, fields) {
        if (err) {
            console.log(err)
            next(err);
        } else {
            res.status(200).json({
                title: "Institución Editada Exitosamente",
                message: 'La institución se ha editado de forma satisfactoria'
            });
        }
    });
});

router.delete('/delete_institucion', verify_token, (req, res, next) => {
    var query = "" +
        " DELETE FROM" +
        " instituciones" +
        " WHERE id = ?";
    var values = [
        req.query.id
    ];
    con.query(query, values, function (err, results, fields) {
        if (err) {
            next(err);
        } else {
            res.status(200).json({
                title: "Institución Eliminada Exitosamente",
                message: 'La institución se ha eliminado de forma satisfactoria'
            });
        }
    });
});

//DOCTORS ##########################################################
//########################################################################
router.get('/email_exists', verify_token, (req, res, next) => {
    let query_string = "";
    query_string = query_string + " SELECT EXISTS (SELECT * FROM doctors WHERE email = '" + request.query.email + "') AS response";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            next(err)
        } else {
            return res.status(200).json({
                title: 'Correo Encontrado',
                message: 'El correo solicitado existe.'
            })
        }
    });
})

router.post('/insert_doctor', verify_token, (request, res, next) => {
    console.log(request.body, 'asdasdasd');

    var query_string = "";
    query_string = query_string + " INSERT INTO users (username,password,user_email,creation_date,profile_id,active,role)";
    query_string = query_string + " VALUES (\"" + request.body.email + "\",SHA1(\"" + request.body.email + "\"),\"" + request.body.email + "\",NOW(),2,1,2);";
    query_string = query_string + " SELECT LAST_INSERT_ID() AS response;";

    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            var foto = "";
            if (request.body.foto !== 'null') {
                foto = request.body.foto;
            }
            var records = [
                [
                    result[0].insertId,
                    request.body.institution_id,
                    request.body.first_name,
                    request.body.last_name,
                    request.body.phone,
                    request.body.extension,
                    request.body.email,
                    request.body.address,
                    request.body.id_card,
                    request.body.id_college,
                    request.body.id_rtn,
                    JSON.stringify(request.body.academic_information),
                    JSON.stringify(request.body.background_information),
                    request.body.position,
                    JSON.stringify(request.body.working_hours),
                    foto
                ],
            ];
            var query_string2 = "";
            query_string2 = query_string2 + " INSERT INTO doctors";
            query_string2 = query_string2 + " (user_id,";
            query_string2 = query_string2 + " institution_id,";
            query_string2 = query_string2 + " first_name,";
            query_string2 = query_string2 + " last_name,";
            query_string2 = query_string2 + " phone,";
            query_string2 = query_string2 + " extension,";
            query_string2 = query_string2 + " email,";
            query_string2 = query_string2 + " address,";
            query_string2 = query_string2 + " id_card,";
            query_string2 = query_string2 + " id_college,";
            query_string2 = query_string2 + " id_rtn,";
            query_string2 = query_string2 + " academic_information,";
            query_string2 = query_string2 + " background_information,";
            query_string2 = query_string2 + " position,";
            query_string2 = query_string2 + " working_hours,";
            query_string2 = query_string2 + " foto)";
            query_string2 = query_string2 + " VALUES ?";
            console.log(query_string2);
            console.log(records);

            con.query(query_string2, [records], function (err2, result2, fields2) {
                if (err2) {
                    console.log(err2);
                    return res.status(500).json({
                        title: 'Error',
                        message: err2.message
                    })
                } else {
                    return res.status(200).json({
                        title: 'Médico ingresado exitosamente',
                        message: 'El médico fue creado de manera satisfactoria'
                    })
                }
            });
        }
    });
})

router.put('/update_doctor', verify_token, (request, res, next) => {
    let foto = "";
    if (request.body.foto != 'null') {
        foto = request.body.foto;
    }
    let query_string = "";
    query_string = query_string + " UPDATE doctors";
    query_string = query_string + " SET institution_id=" + request.body.institution_id + ",";
    query_string = query_string + " first_name='" + request.body.first_name + "',";
    query_string = query_string + " last_name='" + request.body.last_name + "',";
    query_string = query_string + " phone='" + request.body.phone + "',";
    query_string = query_string + " extension='" + request.body.extension + "',";
    query_string = query_string + " email='" + request.body.email + "',";
    query_string = query_string + " address='" + request.body.address + "',";
    query_string = query_string + " id_card='" + request.body.id_card + "',";
    query_string = query_string + " id_college='" + request.body.id_college + "',";
    query_string = query_string + " id_rtn='" + request.body.id_rtn + "',";
    query_string = query_string + " academic_information='" + request.body.academic_information + "',";
    query_string = query_string + " background_information='" + request.body.background_information + "',";
    query_string = query_string + " position='" + request.body.position + "',";
    query_string = query_string + " working_hours='" + request.body.working_hours + "',";
    query_string = query_string + " foto='" + foto + "'";
    query_string = query_string + " WHERE doctor_id=" + request.body.doctor_id + ";";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Médico Actualizado Exitosamente',
                message: "El médico ha sido actualizado de manera satisfactoria"
            })
        }
    });
})

router.delete('/delete_doctor', verify_token, (request, res, next) => {
    let query_string = "";
    query_string = query_string + " DELETE FROM doctors";
    query_string = query_string + " WHERE doctor_id = " + request.query.doctor_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Médico Eliminado Exitosamente',
                message: "El médico ha sido eliminado de manera satisfactoria"
            })
        }
    });
})

router.get('/get_doctor', verify_token, (request, res, next) => {
    let query_string = "";
    query_string = query_string + " SELECT doctors.*, users.username, institutions.name as institution_name FROM doctors";
    query_string = query_string + " INNER JOIN institutions ON doctors.institution_id = institutions.institution_id";
    query_string = query_string + " INNER JOIN users ON doctors.user_id = users.user_id";
    query_string = query_string + " WHERE doctor_id = " + request.query.doctor_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
})

router.get('/doctors_list', verify_token, (request, res, next) => {
    let query_string = "";
    query_string = query_string + " SELECT doctors.*, users.username, instituciones.nombre as institution_name FROM doctors";
    query_string = query_string + " INNER JOIN instituciones ON doctors.institution_id = instituciones.id";
    query_string = query_string + " INNER JOIN users ON doctors.user_id = users.id";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
})

router.get('/doctors_institution_list', verify_token, (request, res, next) => {
    let query_string = "";
    query_string = query_string + " SELECT doctors.*, users.username FROM doctors";
    query_string = query_string + " INNER JOIN users ON doctors.user_id = users.id";
    query_string = query_string + " WHERE doctors.institution_id = " + request.query.institution_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
})

router.post('/insert_patient', verify_token, (request, res, next) => {
    let foto = "";
    if (request.body.foto != 'null') {
        foto = request.body.foto;
    }
    let records = [
        [
            request.body.tipo_paciente,
            request.body.institution_id,
            request.body.first_name,
            request.body.last_name,
            request.body.gender,
            request.body.grado,
            request.body.birth_place,
            request.body.birth_date,
            request.body.address_place,
            request.body.address_avenue,
            request.body.address_street,
            request.body.address_block,
            request.body.address_house,
            request.body.address_city,
            request.body.address_state,
            request.body.seccion,
            request.body.phone,
            JSON.stringify(request.body.emergency_contacts),
            foto
        ],
    ];
    let query_string = "";
    query_string = query_string + " INSERT INTO patients";
    query_string = query_string + " (tipo_paciente,";
    query_string = query_string + " institution_id,";
    query_string = query_string + " first_name,";
    query_string = query_string + " last_name,";
    query_string = query_string + " gender,";
    query_string = query_string + " grado,";
    query_string = query_string + " birth_place,";
    query_string = query_string + " birth_date,";
    query_string = query_string + " address_place,";
    query_string = query_string + " address_avenue,";
    query_string = query_string + " address_street,";
    query_string = query_string + " address_block,";
    query_string = query_string + " address_house,";
    query_string = query_string + " address_city,";
    query_string = query_string + " address_state,";
    query_string = query_string + " seccion,";
    query_string = query_string + " phone,";
    query_string = query_string + " emergency_contacts,";
    query_string = query_string + " foto)";
    query_string = query_string + " VALUES ?";

    con.query(query_string, [records], function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Alumno ingresado exitosamente',
                message: 'El alumno fue creado de manera satisfactoria'
            })
        }
    });
})

router.put('/update_patient', verify_token, (request, res, next) => {
    let foto = "";
    if (request.body.foto != 'null') {
        foto = request.body.foto;
    }
    let query_string = "";
    query_string = query_string + " UPDATE patients";
    query_string = query_string + " SET institution_id=" + request.body.institution_id + ",";
    query_string = query_string + " tipo_paciente='" + request.body.tipo_paciente + "',";
    query_string = query_string + " first_name='" + request.body.first_name + "',";
    query_string = query_string + " last_name='" + request.body.last_name + "',";
    query_string = query_string + " id_card='" + request.body.id_card + "',";
    query_string = query_string + " gender='" + request.body.gender + "',";
    query_string = query_string + " birth_place='" + request.body.birth_place + "',";
    query_string = query_string + " birth_date='" + request.body.birth_date + "',";
    query_string = query_string + " address_place='" + request.body.address_place + "',";
    query_string = query_string + " address_avenue='" + request.body.address_avenue + "',";
    query_string = query_string + " address_street='" + request.body.address_street + "',";
    query_string = query_string + " address_block='" + request.body.address_block + "',";
    query_string = query_string + " address_house='" + request.body.address_house + "',";
    query_string = query_string + " address_city='" + request.body.address_city + "',";
    query_string = query_string + " address_state='" + request.body.address_state + "',";
    query_string = query_string + " phone='" + request.body.phone + "',";
    query_string = query_string + " emergency_contacts='" + request.body.emergency_contacts + "',";
    query_string = query_string + " foto='" + foto + "'";
    query_string = query_string + " WHERE patient_id=" + request.body.patient_id + ";";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result);
        }
    });
})

router.delete('/delete_patient', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " DELETE FROM patients";
    query_string = query_string + " WHERE patient_id = " + request.query.patient_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500), json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result);
        }
    });
})

router.get('/patient_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT patients.*, instituciones.nombre as institution_name FROM patients";
    query_string = query_string + " INNER JOIN instituciones ON patients.institution_id = instituciones.id";;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result);
        }
    });
})

router.get('/patients_institution_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT patients.*, instituciones.nombre as institution_name FROM patients";
    query_string = query_string + " INNER JOIN instituciones on patients.institution_id = instituciones.id";
    query_string = query_string + " WHERE patients.institution_id = " + request.query.institution_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result);
        }
    });
})

router.post('/insert_medicamento', verify_token, (request, res, next) => {
    let records = [
        [
            request.body.nombre,
            request.body.nombre_comercial,
            request.body.presentacion,
            request.body.concentracion,
            request.body.product_id
        ],
    ];
    let query_string = "";
    query_string = query_string + " INSERT INTO medicamentos";
    query_string = query_string + " (nombre,";
    query_string = query_string + " nombre_comercial,";
    query_string = query_string + " presentacion,";
    query_string = query_string + " concentracion,";
    query_string = query_string + " product_id)";
    query_string = query_string + " VALUES ?";

    con.query(query_string, [records], function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Medicamento ingresado exitosamente',
                message: 'El medicamento fue creado de manera satisfactoria',
                medicamento_id: result.insertId
            })
        }
    });
})

router.post('/insert_insumo', verify_token, (request, res, next) => {
    let records = [
        [
            request.body.tipo_insumo,
            request.body.nombre_comercial,
            request.body.presentacion,
            request.body.product_id,
        ],
    ];
    let query_string = "";
    query_string = query_string + " INSERT INTO insumos";
    query_string = query_string + " (tipo_insumo,";
    query_string = query_string + " nombre_comercial,";
    query_string = query_string + " presentacion,";
    query_string = query_string + " product_id)";
    query_string = query_string + " VALUES ?";

    con.query(query_string, [records], function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Insumo ingresado exitosamente',
                message: 'El insumo fue creado de manera satisfactoria',
                insumo_id: result.insertId
            })
        }
    });
})

router.get('/get_inventario_medicamento', verify_token, (request, res, next) => {
    let query_string = "";
    query_string = query_string + " SELECT inventario_medicamentos.*, medicamentos.nombre as inventory_name, products.product_id as product_id, batchs.batch_id as batch_id FROM inventario_medicamentos";
    query_string = query_string + " INNER JOIN medicamentos ON inventario_medicamentos.medicamento_id = medicamentos.medicamento_id";
    query_string = query_string + " INNER JOIN products ON medicamentos.product_id = products.product_id";
    query_string = query_string + " INNER JOIN batchs ON products.product_id = batchs.product_id";
    query_string = query_string + " WHERE inventario_medicamentos.saldo_inventario > 0";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result);
        }
    });
})

router.get('/get_inventario_insumo', verify_token, (request, res, next) => {
    let query_string = "";
    query_string = query_string + " SELECT inventario_insumos.*, insumos.tipo_insumo as inventory_name, products.product_id as product_id, batchs.batch_id as batch_id FROM inventario_insumos";
    query_string = query_string + " INNER JOIN insumos ON inventario_insumos.insumo_id = insumos.insumo_id";
    query_string = query_string + " INNER JOIN products ON insumos.product_id = products.product_id";
    query_string = query_string + " INNER JOIN batchs ON products.product_id = batchs.product_id";
    query_string = query_string + " WHERE inventario_insumos.saldo_inventario > 0";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result);
        }
    });
})

router.post('/insert_cartera_medicamento', verify_token, (request, res, next) => {
    let records = [
        [
            request.body.cartera_id,
            request.body.medicamento_id,
            request.body.cantidad,
            request.body.product_id
        ],
    ];
    let query_string = "";
    query_string = query_string + " INSERT INTO cartera_medicamentos";
    query_string = query_string + " (cartera_id,";
    query_string = query_string + " medicamento_id,";
    query_string = query_string + " cantidad,";
    query_string = query_string + " product_id)";
    query_string = query_string + " VALUES ?";
    
    con.query(query_string, [records], function (err, result, fields) {
        if (err) {
            console.log(err.message);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            let query_string2 = "";
            query_string2 = query_string2 + " SELECT * FROM inventario_medicamentos";
            query_string2 = query_string2 + " WHERE medicamento_id = " + request.body.medicamento_id;
            query_string2 = query_string2 + " ORDER BY vencimiento";
            con.query(query_string, function (err2, result2, fields) {
                if (err2) {
                    console.log(err2);
                    return res.status(500).json({
                        title: 'Error',
                        message: err2.message
                    })
                } else {
                    query_string3 = query_string3 + " UPDATE inventario_medicamentos";
                    query_string3 = query_string3 + " SET en_cartera=" + (Number(result2[0].en_cartera) - Number(request.body.cantidad)) + ",";
                    query_string3 = query_string3 + " saldo_inventario=" + (Number(result2[0].saldo_inventario) - Number(request.body.cantidad)) + ",";
                    query_string3 = query_string3 + " salida_inventario=" + (Number(result2[0].salida_inventario) + Number(request.body.cantidad));
                    query_string3 = query_string3 + " WHERE inventario_id=" + result2[0].inventario_id + ";";
                    con.query(query_string, function (err3, result3, fields) {
                        if (err3) {
                            console.log(err3);
                            return res.status(500).json({
                                title: 'Error',
                                message: err3.message
                            })
                        } else {
                            return res.status(200).json({
                                title: 'Medicamento ingresado en cartera exitosamente',
                                message: 'El medicamento fue insertado de manera satisfactoria',
                                insumo_id: result.insertId
                            })
                        }
                    })
                }
            });
        }
    });
})

router.post('/insert_medicamento_utilizado', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM cartera_medicamentos";
    query_string = query_string + " WHERE cartera_medicamentos_id = " + request.body.cartera_medicamentos_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            var query_string2 = "";
            query_string2 = query_string2 + " SELECT * FROM  inventario_medicamentos";
            query_string2 = query_string2 + " WHERE inventario_id=" + result[0].inventario_id + ";";
            con.query(query_string2, function (err, result2, fields) {
                if (err) {
                    console.log(err);
                    return res.status(500).json({
                        title: 'Error',
                        message: err.message
                    })
                } else {
                    if (Number(result[0].cantidad) >= Number(request.body.cantidad)) {
                        var query_string3 = "";
                        query_string3 = query_string3 + " UPDATE inventario_medicamentos";
                        query_string3 = query_string3 + " SET en_cartera=" + (Number(result2[0].en_cartera) - Number(request.body.cantidad)) + ",";
                        query_string3 = query_string3 + " saldo_inventario=" + (Number(result2[0].saldo_inventario) - Number(request.body.cantidad)) + ",";
                        query_string3 = query_string3 + " salida_inventario=" + (Number(result2[0].salida_inventario) + Number(request.body.cantidad));
                        query_string3 = query_string3 + " WHERE inventario_id=" + result[0].inventario_id + ";";
                        query_string3 = query_string3 + " UPDATE cartera_medicamentos";
                        query_string3 = query_string3 + " SET cantidad=" + (Number(result[0].cantidad) - Number(request.body.cantidad));
                        query_string3 = query_string3 + " WHERE cartera_medicamentos_id=" + request.body.cartera_medicamentos_id + ";";
                        con.query(query_string3, function (err, result3, fields) {
                            if (err) {
                                console.log(err);
                                return res.status(500).json({
                                    title: 'Error',
                                    message: err.message
                                })
                            } else {
                                var records = [
                                    [
                                        request.body.consulta_id,
                                        request.body.cartera_medicamentos_id,
                                        request.body.cantidad
                                    ],
                                ];
                                var query_string4 = "";
                                query_string4 = query_string4 + " INSERT INTO medicamentos_utilizados";
                                query_string4 = query_string4 + " (consulta_id,";
                                query_string4 = query_string4 + " cartera_medicamentos_id,";
                                query_string4 = query_string4 + " cantidad)";
                                query_string4 = query_string4 + " VALUES ?";

                                con.query(query_string4, [records], function (err, result4, fields) {
                                    if (err) {
                                        console.log(err);
                                        return res.status(500).json({
                                            title: 'Error',
                                            message: err.message
                                        })
                                    } else {
                                        return res.status(200).json({
                                            title: 'Operacion realizada con exito',
                                            message: 'La operacion fue realizada de manera satisfactoria'
                                        })
                                    }
                                });
                            }
                        });
                    } else {
                        return res.status(500).json({
                            title: 'Error',
                            message: 'Error interno del servidor'
                        })
                    }
                }
            });

        }
    });
});

router.post('/insert_insumo_utilizado', verify_token, (request, res, next) => {

    var query_string = "";
    query_string = query_string + " SELECT * FROM cartera_insumos";
    query_string = query_string + " WHERE cartera_insumos_id = " + request.body.cartera_insumos_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            var query_string2 = "";
            query_string2 = query_string2 + " SELECT * FROM  inventario_insumos";
            query_string2 = query_string2 + " WHERE inventario_id=" + result[0].inventario_id + ";";
            con.query(query_string2, function (err, result2, fields) {
                if (err) {
                    return res.status(500).json({
                        title: 'Error',
                        message: err.message
                    })
                } else {
                    if (Number(result[0].cantidad) >= Number(request.body.cantidad)) {
                        var query_string3 = "";
                        query_string3 = query_string3 + " UPDATE inventario_insumos";
                        query_string3 = query_string3 + " SET en_cartera=" + (Number(result2[0].en_cartera) - Number(request.body.cantidad)) + ",";
                        query_string3 = query_string3 + " saldo_inventario=" + (Number(result2[0].saldo_inventario) - Number(request.body.cantidad)) + ",";
                        query_string3 = query_string3 + " salida_inventario=" + (Number(result2[0].salida_inventario) + Number(request.body.cantidad));
                        query_string3 = query_string3 + " WHERE inventario_id=" + result[0].inventario_id + ";";
                        query_string3 = query_string3 + " UPDATE cartera_insumos";
                        query_string3 = query_string3 + " SET cantidad=" + (Number(result[0].cantidad) - Number(request.body.cantidad));
                        query_string3 = query_string3 + " WHERE cartera_insumos_id=" + request.body.cartera_insumos_id + ";";
                        con.query(query_string3, function (err, result3, fields) {
                            if (err) {
                                console.log(err);
                                return res.status(500).json({
                                    title: 'Error',
                                    message: err.message
                                })
                            } else {
                                var records = [
                                    [
                                        request.body.consulta_id,
                                        request.body.cartera_insumos_id,
                                        request.body.cantidad
                                    ],
                                ];
                                var query_string4 = "";
                                query_string4 = query_string4 + " INSERT INTO insumos_utilizados";
                                query_string4 = query_string4 + " (consulta_id,";
                                query_string4 = query_string4 + " cartera_insumos_id,";
                                query_string4 = query_string4 + " cantidad)";
                                query_string4 = query_string4 + " VALUES ?";

                                con.query(query_string4, [records], function (err, result4, fields) {
                                    if (err) {
                                        console.log(err);
                                        return res.status(500).json({
                                            title: 'Error',
                                            message: err.message
                                        })
                                    } else {
                                        return res.status(200).json({
                                            title: 'Operacion realizada con exito',
                                            message: 'La operacion fue realizada de manera satisfactoria'
                                        })
                                    }
                                });
                            }
                        });
                    } else {
                        return res.status(500).json({
                            title: 'Error',
                            message: 'Error interno del servidor'
                        })
                    }
                }
            });

        }
    });
})

router.post('/insert_inventario_medicamento', verify_token, (request, res, next) => {
    let records = [
        [
            request.body.costo_compra,
            request.body.cantidad_dosis,
            (parseFloat(request.body.costo_compra) / parseFloat(request.body.cantidad_dosis)),
            request.body.entrada_inventario,
            0,
            request.body.entrada_inventario,
            request.body.numero_inventario,
            0,
            request.body.entrada_inventario,
            request.body.medicamento_id,
        ],
    ];
    let query_string = "";
    query_string = query_string + " INSERT INTO inventario_medicamentos";
    query_string = query_string + " (costo_compra,";
    query_string = query_string + " cantidad_dosis,";
    query_string = query_string + " costo_dosis,";
    query_string = query_string + " entrada_inventario,";
    query_string = query_string + " salida_inventario,";
    query_string = query_string + " saldo_inventario,";
    query_string = query_string + " numero_inventario,";
    query_string = query_string + " en_cartera,";
    query_string = query_string + " sin_cartera,";
    query_string = query_string + " medicamento_id)";
    query_string = query_string + " VALUES ?";

    con.query(query_string, [records], function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Medicamento ingresado exitosamente al inventario',
                message: 'El medicamento fue creado de manera satisfactoria',
                medicamento_id: result.insertId
            })
        }
    });
})

router.post('/insert_inventario_insumos', verify_token, (request, res, next) => {
    let records = [
        [
            request.body.costo_compra,
            (parseFloat(request.body.costo_compra) / parseFloat(request.body.cantidad)),
            request.body.cantidad,
            request.body.entrada_inventario,
            0,
            request.body.entrada_inventario,
            request.body.numero_inventario,
            0,
            request.body.entrada_inventario,
            request.body.insumo_id,
        ],
    ];
    let query_string = "";
    query_string = query_string + " INSERT INTO inventario_insumos";
    query_string = query_string + " (costo_compra,";
    query_string = query_string + " costos_atencion,";
    query_string = query_string + " cantidad,";
    query_string = query_string + " entrada_inventario,";
    query_string = query_string + " salida_inventario,";
    query_string = query_string + " saldo_inventario,";
    query_string = query_string + " numero_inventario,";
    query_string = query_string + " en_cartera,";
    query_string = query_string + " sin_cartera,";
    query_string = query_string + " insumo_id)";
    query_string = query_string + " VALUES ?";

    con.query(query_string, [records], function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Insumo ingresado exitosamente al inventario',
                message: 'El insumo fue creado de manera satisfactoria',
                medicamento_id: result.insertId
            })
        }
    });
})

router.get('/get_medicamentos_utilizados_consulta_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT medicamentos_utilizados.medicamento_utilizado_id, medicamentos_utilizados.cantidad as cantidad_utilizada, medicamentos.nombre, medicamentos.nombre_comercial, inventario_medicamentos.numero_inventario FROM medicamentos_utilizados";
    query_string = query_string + " INNER JOIN cartera_medicamentos ON cartera_medicamentos.cartera_medicamentos_id = medicamentos_utilizados.cartera_medicamentos_id";
    query_string = query_string + " INNER JOIN medicamentos ON medicamentos.medicamento_id = cartera_medicamentos.medicamento_id";
    query_string = query_string + " INNER JOIN inventario_medicamentos ON cartera_medicamentos.inventario_id = inventario_medicamentos.inventario_id";
    query_string = query_string + " WHERE medicamentos_utilizados.consulta_id = " + request.query.consulta_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Operacion realizada con exito',
                message: 'La operacion fue realizada de manera satisfactoria'
            })
        }
    });
});

router.get('/get_insumos_utilizados_consulta_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT insumos_utilizados.insumo_utilizado_id, insumos_utilizados.cantidad as cantidad_utilizada, insumos.tipo_insumo, insumos.nombre_comercial, inventario_insumos.numero_inventario FROM insumos_utilizados";
    query_string = query_string + " INNER JOIN cartera_insumos ON cartera_insumos.cartera_insumos_id = insumos_utilizados.cartera_insumos_id";
    query_string = query_string + " INNER JOIN insumos ON insumos.insumo_id = cartera_insumos.insumo_id";
    query_string = query_string + " INNER JOIN inventario_insumos ON cartera_insumos.inventario_id = inventario_insumos.inventario_id";
    query_string = query_string + " WHERE insumos_utilizados.consulta_id = " + request.query.consulta_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Operacion realizada con exito',
                message: 'La operacion fue realizada de manera satisfactoria'
            })
        }
    });
});

router.post('/insert_producto', verify_token, (request, res, next) => {
    var records = [
        [
            request.body.tradename_id,
            request.body.presentation_id,
            request.body.concentration_id,
            request.body.presentation_quantity,
            request.body.presentation_measure_unit_id,
            request.body.aus_quantity,
            request.body.aus_measure_unit_id,
            request.body.description
        ],
    ];
    var query_string = "";
    query_string = query_string + " INSERT INTO products";
    query_string = query_string + " (tradename_id,";
    query_string = query_string + " presentation_id,";
    query_string = query_string + " concentration_id,";
    query_string = query_string + " presentation_quantity,";
    query_string = query_string + " presentation_measure_unit_id,";
    query_string = query_string + " aus_quantity,";
    query_string = query_string + " aus_measure_unit_id,";
    query_string = query_string + " description)";
    query_string = query_string + " VALUES ?";

    con.query(query_string, [records], function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Operacion realizada con exito',
                message: 'La operacion fue realizada de manera satisfactoria',
                result
            })
        }
    });
});

router.put('/update_producto', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " UPDATE products";
    query_string = query_string + " SET presentation_id=" + request.body.presentation_id + ",";
    query_string = query_string + " concentration_id=" + request.body.concentration_id + ",";
    query_string = query_string + " presentation_quantity=" + request.body.presentation_quantity + ",";
    query_string = query_string + " presentation_measure_unit_id=" + request.body.presentation_measure_unit_id + ",";
    query_string = query_string + " aus_quantity=" + request.body.aus_quantity + ",";
    query_string = query_string + " aus_measure_unit_id=" + request.body.aus_measure_unit_id + ",";
    query_string = query_string + " tradename_id=" + request.body.tradename_id + "";
    query_string = query_string + " WHERE product_id=" + request.body.product_id + ";";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Operacion realizada con exito',
                message: 'La operacion fue realizada de manera satisfactoria'
            })
        }
    });

});

router.delete('/delete_producto', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT *  FROM batchs";
    query_string = query_string + " WHERE product_id = " + request.query.product_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                reply(-2);
            } else {
                var query_string2 = "";
                query_string2 = query_string2 + " DELETE FROM products";
                query_string2 = query_string2 + " WHERE product_id = " + request.query.product_id;
                con.query(query_string2, function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }
        }
    });
});

router.get('/get_active_principles_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT *  FROM active_principles";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_active_principle', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM active_principles";
    query_string = query_string + " WHERE active_principle_id = " + request.query.active_principle_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return Response.status(200).json(result);
        }
    });
});

router.post('/insert_active_principle', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT name FROM active_principles";
    query_string = query_string + " WHERE name = '" + request.body.name + "'";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                reply(-2);
            } else {
                var records = [
                    [
                        request.body.name,
                        request.body.description
                    ],
                ];
                var query_string1 = "";
                query_string1 = query_string1 + " INSERT INTO active_principles";
                query_string1 = query_string1 + " (name,";
                query_string1 = query_string1 + " description)";
                query_string1 = query_string1 + " VALUES ?";
                con.query(query_string1, [records], function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }

        }
    });
});

router.put('/update_active_principle', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT name FROM active_principles";
    query_string = query_string + " WHERE name = '" + request.body.name + "' AND active_principle_id!=" + request.body.active_principle_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                reply(-2);
            } else {
                var query_string2 = "";
                query_string2 = query_string2 + " UPDATE active_principles";
                query_string2 = query_string2 + " SET name='" + request.body.name + "',";
                query_string2 = query_string2 + " description='" + request.body.description + "'";
                query_string2 = query_string2 + " WHERE active_principle_id=" + request.body.active_principle_id + ";";
                con.query(query_string2, function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }

        }
    });
});

router.delete('/delete_active_principle', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + "  SELECT *  FROM tradenames";
    query_string = query_string + " WHERE active_principle_id = " + request.query.active_principle_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                reply(-2);
            } else {
                var query_string2 = "";
                query_string2 = query_string2 + "  DELETE FROM active_principles";
                query_string2 = query_string2 + " WHERE active_principle_id = " + request.query.active_principle_id;
                con.query(query_string2, function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }
        }
    });

});

router.get('/get_all_medicamentos', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * from medicamentos";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_all_insumos', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * from insumos";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_tradename_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT tradenames.*, active_principles.name as active_principle  FROM tradenames";
    query_string = query_string + " INNER JOIN active_principles on  tradenames.active_principle_id = active_principles.active_principle_id";
    query_string = query_string + " WHERE tradenames.active_principle_id = " + request.query.active_principle_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_tradename', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM tradenames";
    query_string = query_string + " WHERE tradename_id = " + request.query.tradename_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.post('/insert_tradename', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT name FROM tradenames";
    query_string = query_string + " WHERE name = '" + request.body.name + "'";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                return res.status(500).json({
                    title: 'Error',
                    message: 'El nombre comercial ya existe'
                })
            } else {
                var records = [
                    [
                        request.body.active_principle_id,
                        request.body.name,
                        request.body.description
                    ],
                ];
                var query_string1 = "";
                query_string1 = query_string1 + " INSERT INTO tradenames";
                query_string1 = query_string1 + " (active_principle_id,";
                query_string1 = query_string1 + " name,";
                query_string1 = query_string1 + " description)";
                query_string1 = query_string1 + " VALUES ?";
                con.query(query_string1, [records], function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }

        }
    });
});

router.put('/update_tradename', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT name FROM tradenames";
    query_string = query_string + " WHERE name = '" + request.body.name + "' AND tradename_id!=" + request.body.tradename_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                return res.status(500).json({
                    title: 'Error',
                    message: 'error'
                })
            } else {
                var query_string2 = "";
                query_string2 = query_string2 + " UPDATE tradenames";
                query_string2 = query_string2 + " SET name='" + request.body.name + "',";
                query_string2 = query_string2 + " description='" + request.body.description + "'";
                query_string2 = query_string2 + " WHERE tradename_id=" + request.body.tradename_id + ";";
                con.query(query_string2, function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }
        }
    });
});

router.delete('/delete_tradename', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + "  SELECT *  FROM products";
    query_string = query_string + " WHERE tradename_id = " + request.query.tradename_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                reply(-2);
            } else {
                var query_string2 = "";
                query_string2 = query_string2 + "  DELETE FROM tradenames";
                query_string2 = query_string2 + " WHERE tradename_id = " + request.query.tradename_id;
                con.query(query_string2, function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }
        }
    });
});

router.get('/get_presentation_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT *  FROM presentations";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_presentation', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM presentations";
    query_string = query_string + " WHERE presentation_id = " + request.query.presentation_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.post('/insert_presentation', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT name FROM presentations";
    query_string = query_string + " WHERE name = '" + request.body.name + "'";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                console.log('name exists');
                reply(-2);
            } else {
                var records = [
                    [
                        request.body.name,
                        request.body.description
                    ],
                ];
                var query_string1 = "";
                query_string1 = query_string1 + " INSERT INTO presentations";
                query_string1 = query_string1 + " (name,";
                query_string1 = query_string1 + " description)";
                query_string1 = query_string1 + " VALUES ?";
                con.query(query_string1, [records], function (err, result, fields) {
                    if (err) {
                        console.log(err);
                        return res.status(500).json({
                            title: 'Error',
                            message: err.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }

        }
    });
});

router.put('/update_presentation', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " UPDATE presentations";
    query_string = query_string + " SET name='" + request.body.name + "',";
    query_string = query_string + " description='" + request.body.description + "'";
    query_string = query_string + " WHERE presentation_id=" + request.body.presentation_id + ";";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Operacion realizada con exito',
                message: 'La operacion fue realizada de manera satisfactoria'
            })
        }
    });
});

router.delete('/delete_presentation', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + "  DELETE FROM presentations";
    query_string = query_string + " WHERE presentation_id = " + request.query.presentation_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Operacion realizada con exito',
                message: 'La operacion fue realizada de manera satisfactoria'
            })
        }
    });
});

router.get('/get_measure_units_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT *  FROM measure_units";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_measure_unit', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM measure_units";
    query_string = query_string + " WHERE measure_unit_id = " + request.query.measure_unit_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.post('/insert_measure_unit', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT name FROM measure_units";
    query_string = query_string + " WHERE name = '" + request.body.name + "'";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                console.log('name exists');
                reply(-2);
            } else {
                var records = [
                    [
                        request.body.name,
                        request.body.description
                    ],
                ];
                var query_string1 = "";
                query_string1 = query_string1 + " INSERT INTO measure_units";
                query_string1 = query_string1 + " (name,";
                query_string1 = query_string1 + " description)";
                query_string1 = query_string1 + " VALUES ?";
                con.query(query_string1, [records], function (err, result, fields) {
                    if (err) {
                        console.log(err);
                        return res.status(500).json({
                            title: 'Error',
                            message: err.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }

        }
    });
});

router.put('/update_measure_unit', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " UPDATE measure_units";
    query_string = query_string + " SET name='" + request.body.name + "',";
    query_string = query_string + " description='" + request.body.description + "'";
    query_string = query_string + " WHERE measure_unit_id=" + request.body.measure_unit_id + ";";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Operacion realizada con exito',
                message: 'La operacion fue realizada de manera satisfactoria'
            })
        }
    });
});

router.delete('/delete_measure_unit', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + "  DELETE FROM measure_units";
    query_string = query_string + " WHERE measure_unit_id = " + request.query.measure_unit_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Operacion realizada con exito',
                message: 'La operacion fue realizada de manera satisfactoria'
            })
        }
    });
});

router.get('/get_concentrations_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM concentrations";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_concentration', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM concentrations";
    query_string = query_string + " WHERE concentration_id = " + request.query.concentration_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.post('/insert_concentration', verify_token, (request, res, next) => {
    var q2 = null;
    var m2 = null;
    if (request.body.quantity2) {
        q2 = request.body.quantity2;
    }
    if (request.body.measure_unit_id2) {
        m2 = request.body.measure_unit_id2;
    }
    var query_string = "";
    query_string = query_string + " SELECT * FROM concentrations";
    query_string = query_string + " WHERE quantity1 = " + request.body.quantity1 + " AND quantity2 = " + q2 + " AND measure_unit_id1 = " + request.body.measure_unit_id1 + " AND measure_unit_id2 = " + m2;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                return res.status(500).json({
                    title: 'Error',
                    message: 'Existe un item duplicado'
                })
            } else {
                var records = [
                    [
                        request.body.quantity1,
                        request.body.measure_unit_id1,
                        q2,
                        m2,
                        request.body.description
                    ],
                ];
                var query_string = "";
                query_string = query_string + " INSERT  INTO concentrations";
                query_string = query_string + " (quantity1,";
                query_string = query_string + " measure_unit_id1,";
                query_string = query_string + " quantity2,";
                query_string = query_string + " measure_unit_id2,";
                query_string = query_string + " description)";
                query_string = query_string + " VALUES ?";

                con.query(query_string, [records], function (err, result, fields) {
                    if (err) {
                        console.log(err);
                        return res.status(500).json({
                            title: 'Error',
                            message: err.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria',
                            result
                        })
                    }
                });
            }
        }
    });
});

router.put('/update_concentration', verify_token, (request, res, next) => {
    var q2 = null;
    var m2 = null;
    if (request.body.quantity2) {
        q2 = request.body.quantity2;
    }
    if (request.body.measure_unit_id2) {
        m2 = request.body.measure_unit_id2;
    }
    var query_string = "";
    query_string = query_string + " SELECT * FROM concentrations";
    query_string = query_string + " WHERE quantity1 = " + request.body.quantity1 + " AND quantity2 = " + q2 + " AND measure_unit_id1 = " + request.body.measure_unit_id1 + " AND measure_unit_id2 = " + m2 + " AND concentration_id != " + request.body.concentration_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                reply(-2);
            } else {
                var query_string2 = "";
                query_string2 = query_string2 + " UPDATE concentrations";
                query_string2 = query_string2 + " SET quantity1=" + request.body.quantity1 + ",";
                query_string2 = query_string2 + " measure_unit_id1=" + request.body.measure_unit_id1 + ",";
                query_string2 = query_string2 + " quantity2=" + q2 + ",";
                query_string2 = query_string2 + " measure_unit_id2=" + m2 + ",";
                query_string2 = query_string2 + " description='" + request.body.description + "'";
                query_string2 = query_string2 + " WHERE concentration_id=" + request.body.concentration_id + ";";
                con.query(query_string2, function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }
        }
    });
});

router.delete('/delete_concentration', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + "  SELECT *  FROM products";
    query_string = query_string + " WHERE concentration_id = " + request.query.concentration_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                reply(-2);
            } else {
                var query_string2 = "";
                query_string2 = query_string2 + " DELETE FROM concentrations";
                query_string2 = query_string2 + " WHERE concentration_id = " + request.query.concentration_id;
                con.query(query_string2, function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }
        }
    });
});

router.get('/get_batchs_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT batchs.*, ";
    query_string = query_string + " (SELECT COALESCE(sum(cartera_medicamentos.quantity),0) FROM cartera_medicamentos WHERE cartera_medicamentos.batch_id = batchs.batch_id) as batch_assigned,";
    query_string = query_string + " batchs.batch_quantity - (SELECT COALESCE(sum(cartera_medicamentos.quantity),0) FROM cartera_medicamentos WHERE cartera_medicamentos.batch_id = batchs.batch_id) as batch_available,";
    query_string = query_string + " (SELECT COALESCE(sum(cartera_medicamentos.quantity),0) FROM cartera_medicamentos WHERE cartera_medicamentos.batch_id = batchs.batch_id) as batch_used";
    query_string = query_string + " FROM batchs";
    query_string = query_string + " WHERE product_id = " + request.query.product_id;
    query_string = query_string + " ORDER BY batchs.expiration_date, batchs.purchase_date";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_batch', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM batchs";
    query_string = query_string + " WHERE batch_id = " + request.query.batch_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_search_batch', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM batchs";
    query_string = query_string + "  WHERE expiration_date LIKE '%" + request.query.expiration_date + "%'";
    console.log(query_string);
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                return res.status(200).json(result)
            } else {
                console.log('No Existe')
                reply(-2);
            }
        }
    });
});

router.post('/insert_batch', verify_token, (request, res, next) => {
    var records = [
        [
            request.body.product_id,
            request.body.expiration_date,
            request.body.purchase_date,
            request.body.batch_price,
            request.body.batch_quantity,
            request.body.observation
        ],
    ];
    var query_string1 = "";
    query_string1 = query_string1 + " INSERT INTO batchs";
    query_string1 = query_string1 + " (product_id,";
    query_string1 = query_string1 + " expiration_date,";
    query_string1 = query_string1 + " purchase_date,";
    query_string1 = query_string1 + " batch_price,";
    query_string1 = query_string1 + " batch_quantity,";
    query_string1 = query_string1 + " observation)";
    query_string1 = query_string1 + " VALUES ?";
    con.query(query_string1, [records], function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Operacion realizada con exito',
                message: 'La operacion fue realizada de manera satisfactoria'
            })
        }
    });
});

router.put('/update_batch', verify_token, (request, res, next) => {
    var query_string2 = "";
    query_string2 = query_string2 + " SELECT COALESCE(sum(cartera_medicamentos.quantity),0) as used_quantity";
    query_string2 = query_string2 + " FROM cartera_medicamentos ";
    query_string2 = query_string2 + " WHERE cartera_medicamentos.batch_id = " + request.body.batch_id + ";";
    con.query(query_string2, function (err2, result2, fields2) {
        if (err2) {
            console.log(err2);
            return res.status(500).json({
                title: 'Error',
                message: err2.message
            })
        } else {
            if (result2 && result2[0] && request.body.batch_quantity >= result2[0].used_quantity) {
                var query_string = "";
                query_string = query_string + " UPDATE batchs";
                query_string = query_string + " SET product_id='" + request.body.product_id + "',";
                query_string = query_string + " expiration_date='" + request.body.expiration_date + "',";
                query_string = query_string + " purchase_date='" + request.body.purchase_date + "',";
                query_string = query_string + " batch_price='" + request.body.batch_price + "',";
                query_string = query_string + " batch_quantity='" + request.body.batch_quantity + "',";
                query_string = query_string + " observation='" + request.body.observation + "'";
                query_string = query_string + " WHERE batch_id=" + request.body.batch_id + ";";
                con.query(query_string, function (err, result, fields) {
                    if (err) {
                        console.log(err);
                        return res.status(500).json({
                            title: 'Error',
                            message: err.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            } else {
                reply(-2);
            }
        }
    });
});

router.delete('/delete_batch', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT *  FROM cartera_medicamentos";
    query_string = query_string + " WHERE batch_id = " + request.query.batch_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                reply(-2);
            } else {
                var query_string2 = "";
                query_string2 = query_string2 + "  DELETE FROM batchs";
                query_string2 = query_string2 + " WHERE batch_id = " + request.query.batch_id;
                con.query(query_string2, function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }
        }
    });
});

router.get('/get_products', verify_token, (request, res, next) => {
    let query_string = "";
    query_string = query_string + " SELECT * FROM products";
    query_string = query_string + " INNER JOIN medicamentos ON products.product_id = medicamentos.product_id";
    con.query(query_string, function (err1, result1, fields) {
        if (err1) {
            console.log(err1);
            return res.status(500).json({
                title: 'Error',
                message: err1.message
            })
        } else {
            let query_string2 = "";
            query_string2 = query_string2 + " SELECT * FROM products";
            query_string2 = query_string2 + " INNER JOIN insumos ON products.product_id = insumos.product_id";
            con.query(query_string2, function (err2, result2, fields) {
                if (err2) {
                    console.log(err2);
                    return res.status(500).json({
                        title: 'Error',
                        message: err2.message
                    })
                } else {
                    return res.status(200).json(
                        {
                            medicamentos: result1,
                            insumos: result2
                        }
                    )
                }
            });
        }
    });
});

router.get('/get_products_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT products.*, tradenames.name as tradename_name, tradenames.description as tradename_description, active_principles.active_principle_id as active_principle_id, active_principles.name as active_principle_name, active_principles.description as active_principle_description, presentations.name as presentation_name, concentrations.description as concentration_name, m1.name as presentation_measure_unit_name, m2.name as aus_measure_unit_name,";
    query_string = query_string + " (select COALESCE(sum(batchs.batch_quantity),0) from batchs where batchs.product_id = products.product_id) - (select COALESCE(sum(cartera_medicamentos.cantidad),0) from cartera_medicamentos where cartera_medicamentos.product_id = products.product_id) as cantidad_disponible_bodega,";
    query_string = query_string + " ((select COALESCE(sum(batchs.batch_quantity),0) from batchs where batchs.product_id = products.product_id) - (select COALESCE(sum(cartera_medicamentos.cantidad),0) from cartera_medicamentos where cartera_medicamentos.product_id = products.product_id)) *products.presentation_quantity/products.aus as cantidad_aus";
    query_string = query_string + " FROM products";
    query_string = query_string + " INNER JOIN tradenames ON products.tradename_id= tradenames.tradename_id";
    query_string = query_string + " INNER JOIN active_principles ON tradenames.active_principle_id= active_principles.active_principle_id";
    query_string = query_string + " INNER JOIN presentations ON products.presentation_id= presentations.presentation_id";
    query_string = query_string + " INNER JOIN concentrations ON products.concentration_id= concentrations.concentration_id";
    query_string = query_string + " INNER JOIN measure_units as m1 ON m1.measure_unit_id= products.presentation_measure_unit_id";
    query_string = query_string + " INNER JOIN measure_units as m2 ON m2.measure_unit_id= products.aus_measure_unit_id";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(
                result
            )
        }
    });
});

router.get('/get_product', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT pro.product_id, tra.name nombre_comercial, pre.name presentacion, concat(con.quantity1, mea.name) concentracion1, concat(con.quantity2, mea.name) concentracion2, pro.presentation_quantity catidad_presentacion, act.name activo_principal, bat.expiration_date fecha_vence";
    query_string = query_string + " FROM products pro";
    query_string = query_string + " INNER JOIN tradenames tra ON pro.tradename_id= tra.tradename_id";
    query_string = query_string + " INNER JOIN presentations pre ON pro.presentation_id= pre.presentation_id";
    query_string = query_string + " INNER JOIN concentrations con ON pro.product_id= con.concentration_id";
    query_string = query_string + " INNER JOIN measure_units mea ON con.measure_unit_id1= mea.measure_unit_id";
    query_string = query_string + " INNER JOIN active_principles act ON  tra.active_principle_id= act.active_principle_id";
    query_string = query_string + " INNER JOIN batchs bat ON pro.product_id= bat.product_id";
    query_string = query_string + " WHERE pro.product_id = " + request.query.product_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_active_principle_total_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT ";
    query_string = query_string + " active_principles.active_principle_id as active_principle_id, ";
    query_string = query_string + " active_principles.name as active_principle_name, ";
    query_string = query_string + " active_principles.description as active_principle_description, ";
    query_string = query_string + " products.aus_quantity,";
    query_string = query_string + " sum(batchs.batch_quantity) as cantidad_bodega,";
    query_string = query_string + " sum(batchs.batch_quantity*products.presentation_quantity/products.aus_quantity) as cantidad_aus,";
    query_string = query_string + " presentations.name as presentation_name,";
    query_string = query_string + " m1.name as presentation_measure_unit_name, ";
    query_string = query_string + " m2.name as aus_measure_unit_name";
    query_string = query_string + " FROM products";
    query_string = query_string + " INNER JOIN tradenames ON products.tradename_id= tradenames.tradename_id";
    query_string = query_string + " INNER JOIN active_principles ON tradenames.active_principle_id= active_principles.active_principle_id";
    query_string = query_string + " INNER JOIN presentations ON products.presentation_id= presentations.presentation_id";
    query_string = query_string + " INNER JOIN measure_units as m1 ON m1.measure_unit_id= products.presentation_measure_unit_id";
    query_string = query_string + " INNER JOIN measure_units as m2 ON m2.measure_unit_id= products.aus_measure_unit_id";
    query_string = query_string + " INNER JOIN batchs ON batchs.product_id = products.product_id";
    query_string = query_string + " GROUP BY active_principles.active_principle_id, presentations.presentation_id";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.get('/get_batchs_for_asign_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT *";
    query_string = query_string + " FROM(";
    query_string = query_string + " SELECT batchs.batch_id, ";
    query_string = query_string + " batchs.purchase_date, batchs.expiration_date, batchs.batch_quantity, ";
    query_string = query_string + " (SELECT COALESCE(sum(cartera_medicamentos.quantity),0) FROM cartera_medicamentos WHERE cartera_medicamentos.batch_id = batchs.batch_id) as batch_assigned,";
    query_string = query_string + " batchs.batch_quantity - (SELECT COALESCE(sum(cartera_medicamentos.quantity),0) FROM cartera_medicamentos WHERE cartera_medicamentos.batch_id = batchs.batch_id) as batch_available";
    query_string = query_string + " FROM batchs";
    query_string = query_string + " WHERE batchs.product_id = " + request.query.product_id;
    query_string = query_string + " ORDER BY batchs.expiration_date, batchs.purchase_date) as b";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

router.post('/insert_cartera', verify_token, (request, res, next) => {
    let records = [
        [
            request.body.institution_id,
            request.body.nombre,
            request.body.descripcion,
        ],
    ];
    let query_string = "";
    query_string = query_string + " INSERT INTO carteras";
    query_string = query_string + " (institution_id,";
    query_string = query_string + " nombre,";
    query_string = query_string + " descripcion)";
    query_string = query_string + " VALUES ?";

    con.query(query_string, [records], function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json({
                title: 'Cartera ingresada exitosamente',
                message: 'La cartera fue creada de manera satisfactoria',
                medicamento_id: result.insertId
            })
        }
    });
})

router.post('/insert_cartera_productos', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT *";
    query_string = query_string + " FROM(";
    query_string = query_string + " SELECT batchs.batch_id, ";
    query_string = query_string + " batchs.purchase_date, batchs.expiration_date, batchs.batch_quantity, ";
    query_string = query_string + " (SELECT COALESCE(sum(cartera_medicamentos.quantity),0) FROM cartera_medicamentos WHERE cartera_medicamentos.batch_id = batchs.batch_id) as batch_assigned,";
    query_string = query_string + " batchs.batch_quantity - (SELECT COALESCE(sum(cartera_medicamentos.quantity),0) FROM cartera_medicamentos WHERE cartera_medicamentos.batch_id = batchs.batch_id) as batch_available";
    query_string = query_string + " FROM batchs";
    query_string = query_string + " WHERE batchs.product_id = " + request.body.product_id;
    query_string = query_string + " ORDER BY batchs.expiration_date, batchs.purchase_date) as b";
    query_string = query_string + " WHERE b.batch_id = " + request.body.batch_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result && result[0] && result[0].batch_available >= request.body.quantity) {
                var records = [
                    [
                        request.body.cartera_id,
                        request.body.product_id,
                        request.body.batch_id,
                        request.body.quantity
                    ],
                ];
                var query_string1 = "";
                query_string1 = query_string1 + " INSERT INTO cartera_medicamentos";
                query_string1 = query_string1 + " (cartera_id,";
                query_string1 = query_string1 + " product_id,";
                query_string1 = query_string1 + " batch_id,";
                query_string1 = query_string1 + " quantity)";
                query_string1 = query_string1 + " VALUES ?";
                con.query(query_string1, [records], function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            } else {
                reply(-2);
            }
        }
    });
});

router.put('/update_cartera_productos', verify_token, (request, res, next) => {
    var query_string3 = "";
    query_string3 = query_string3 + " SELECT COALESCE(sum(medicamentos_utilizados.cantidad),0) as used_quantity";
    query_string3 = query_string3 + " FROM medicamentos_utilizados ";
    query_string3 = query_string3 + " WHERE medicamentos_utilizados.cartera_medicamentos_id = " + request.body.cartera_medicamentos_id;
    con.query(query_string3, function (err3, result3, fields3) {
        if (err3) {
            console.log(err3);
            return res.status(500).json({
                title: 'Error',
                message: err3.message
            })
        } else {
            if (result3 && result3[0] && request.body.quantity >= result3[0].used_quantity) {
                var query_string = "";
                query_string = query_string + " SELECT *";
                query_string = query_string + " FROM(";
                query_string = query_string + " SELECT batchs.batch_id, ";
                query_string = query_string + " batchs.purchase_date, batchs.expiration_date, batchs.batch_quantity, ";
                query_string = query_string + " (SELECT COALESCE(sum(cartera_medicamentos.quantity),0) FROM cartera_medicamentos WHERE cartera_medicamentos.batch_id = batchs.batch_id) as batch_assigned,";
                query_string = query_string + " batchs.batch_quantity - (SELECT COALESCE(sum(cartera_medicamentos.quantity),0) FROM cartera_medicamentos WHERE cartera_medicamentos.batch_id = batchs.batch_id) as batch_available";
                query_string = query_string + " FROM batchs";
                query_string = query_string + " WHERE batchs.product_id = " + request.body.product_id;
                query_string = query_string + " ORDER BY batchs.expiration_date, batchs.purchase_date) as b";
                query_string = query_string + " WHERE b.batch_id = " + request.body.batch_id;
                con.query(query_string, function (err, result, fields) {
                    if (err) {
                        console.log(err);
                        return res.status(500).json({
                            title: 'Error',
                            message: err.message
                        })
                    } else {
                        var query_string4 = "";
                        query_string4 = query_string4 + " SELECT * FROM cartera_medicamentos";
                        query_string4 = query_string4 + " WHERE cartera_medicamentos_id=" + request.body.cartera_medicamentos_id + ";";
                        con.query(query_string4, function (err4, result4, fields4) {
                            if (err4) {
                                console.log(err4);
                                return res.status(500).json({
                                    title: 'Error',
                                    message: err4.message
                                })
                            } else {
                                if (result && result[0] && (result[0].batch_available + result4[0].quantity) >= request.body.quantity) {
                                    var query_string2 = "";
                                    query_string2 = query_string2 + " UPDATE cartera_medicamentos";
                                    query_string2 = query_string2 + " SET cartera_id=" + request.body.cartera_id + ",";
                                    query_string2 = query_string2 + " product_id=" + request.body.product_id + ",";
                                    query_string2 = query_string2 + " batch_id=" + request.body.batch_id + ",";
                                    query_string2 = query_string2 + " quantity=" + request.body.quantity + "";
                                    query_string2 = query_string2 + " WHERE cartera_medicamentos_id=" + request.body.cartera_medicamentos_id + ";";
                                    con.query(query_string2, function (err2, result2, fields2) {
                                        if (err2) {
                                            console.log(err2);
                                            return res.status(500).json({
                                                title: 'Error',
                                                message: err2.message
                                            })
                                        } else {
                                            return res.status(200).json({
                                                title: 'Operacion realizada con exito',
                                                message: 'La operacion fue realizada de manera satisfactoria'
                                            })
                                        }
                                    });
                                } else {
                                    reply(-2);
                                }
                            }
                        });
                    }
                });
            } else {
                reply(-3);
            }
        }
    });
});

router.get('/get_institution_cartera', verify_token, (request, res, next) => {
    let query_string = "";
    query_string = query_string + " SELECT * from carteras";
    query_string = query_string + " WHERE institution_id = " + request.query.institution_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
})

router.get('/get_cartera_productos_list', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " select cartera_medicamentos.cartera_medicamentos_id,cartera_medicamentos.cartera_id, cartera_medicamentos.batch_id, cartera_medicamentos.product_id,";
    query_string = query_string + " batchs.expiration_date,";
    query_string = query_string + " cartera_medicamentos.quantity-(SELECT COALESCE(sum(medicamentos_utilizados.cantidad),0) FROM medicamentos_utilizados WHERE medicamentos_utilizados.cartera_medicamentos_id = cartera_medicamentos.cartera_medicamentos_id) as available_quantity,";
    query_string = query_string + " (cartera_medicamentos.quantity-(SELECT COALESCE(sum(medicamentos_utilizados.cantidad),0) FROM medicamentos_utilizados WHERE medicamentos_utilizados.cartera_medicamentos_id = cartera_medicamentos.cartera_medicamentos_id))*products.presentation_quantity/products.aus_quantity as available_aus,";
    query_string = query_string + " carteras.nombre,";
    query_string = query_string + " institutions.name as institution,";
    query_string = query_string + " institutions.institution_id,";
    query_string = query_string + " cartera_medicamentos.quantity as quantity";
    query_string = query_string + " FROM cartera_medicamentos";
    query_string = query_string + " INNER JOIN carteras ON cartera_medicamentos.cartera_id= carteras.cartera_id";
    query_string = query_string + " INNER JOIN institutions ON institutions.institution_id= carteras.institution_id";
    query_string = query_string + " INNER JOIN batchs ON batchs.batch_id= cartera_medicamentos.batch_id";
    query_string = query_string + " INNER JOIN products ON cartera_medicamentos.product_id = products.product_id";
    query_string = query_string + " WHERE cartera_medicamentos.product_id = " + request.query.product_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
})

router.delete('/delete_cartera_productos', verify_token, (request, res, next) => {
    var query_string = "";
    query_string = query_string + " SELECT * FROM medicamentos_utilizados";
    query_string = query_string + " WHERE cartera_medicamentos_id = " + request.query.cartera_medicamentos_id;
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            if (result.length > 0) {
                reply(-2);
            } else {
                var query_string2 = "";
                query_string2 = query_string2 + " DELETE FROM cartera_medicamentos";
                query_string2 = query_string2 + " WHERE cartera_medicamentos_id = " + request.query.cartera_medicamentos_id;
                con.query(query_string2, function (err2, result2, fields2) {
                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            title: 'Error',
                            message: err2.message
                        })
                    } else {
                        return res.status(200).json({
                            title: 'Operacion realizada con exito',
                            message: 'La operacion fue realizada de manera satisfactoria'
                        })
                    }
                });
            }
        }
    });
});

router.get('/get_carteras_by_active_principle_list', verify_token, (request, res, next) => {
    query_string = " SELECT";
    query_string = query_string + " tradenames.name as nombre_comercial,";
    query_string = query_string + " carteras.nombre as cartera,";
    query_string = query_string + " institutions.name as instituto,";
    query_string = query_string + " COALESCE(sum(cartera_medicamentos.quantity),0)- (SELECT COALESCE(sum(medicamentos_utilizados.cantidad),0) FROM medicamentos_utilizados WHERE medicamentos_utilizados.cartera_medicamentos_id = cartera_medicamentos.cartera_medicamentos_id) as quantity,";
    query_string = query_string + " (COALESCE(sum(cartera_medicamentos.quantity),0)- (SELECT COALESCE(sum(medicamentos_utilizados.cantidad),0) FROM medicamentos_utilizados WHERE medicamentos_utilizados.cartera_medicamentos_id = cartera_medicamentos.cartera_medicamentos_id))*products.presentation_quantity/products.aus_quantity as aus_quantity";
    query_string = query_string + " FROM cartera_medicamentos";
    query_string = query_string + " INNER JOIN products ON products.product_id = cartera_medicamentos.product_id";
    query_string = query_string + " INNER JOIN tradenames ON tradenames.tradename_id = products.tradename_id";
    query_string = query_string + " INNER JOIN carteras ON carteras.cartera_id = cartera_medicamentos.cartera_id";
    query_string = query_string + " INNER JOIN institutions ON institutions.institution_id = carteras.institution_id";
    query_string = query_string + " WHERE tradenames.active_principle_id = " + request.query.active_principle_id;
    query_string = query_string + " GROUP BY carteras.cartera_id";
    con.query(query_string, function (err, result, fields) {
        if (err) {
            console.log(err);
            return res.status(500).json({
                title: 'Error',
                message: err.message
            })
        } else {
            return res.status(200).json(result)
        }
    });
});

//########################################################################
//GROUPS #################################################################

/*router.get('/get_groups', verify_token, (req, res, next) => {
    var query = "" +
    " SELECT id, grp_nombre FROM" +
    " smsreseller_grupos" +
    " WHERE" +
    " id NOT IN (SELECT smsreseller_gru os_id FROM smsreseller_listacrm)" +
    " AND smsreseller_grupos.tipo = 0" +
    " AND smsadmin_resellers_id = ?";
    var values = [
        req.smsadmin_resellers_id
    ];
    con.query(query, values, function(err, results, fields) {
        if(err) {
            next(err);
        }else{
            res.status(200).json(results);
        }
    });
});

router.post('/insert_group', verify_token, (req, res, next) => {
    var query = "" +
    " INSERT INTO smsreseller_grupos" +
    " (" +
    " grp_nombre," +
    " smsadmin_resellers_id" + 
    " )" +
    " VALUES" +
    " (" +
    " ?," +
    " ?" +
    " )";
    var values = [
        req.body.grp_nombre,
        req.smsadmin_resellers_id
    ];
    con.query(query, values, function(err, results, fields) {
        if(err){
            next(err);
        }else{
            res.status(200).json({
                title:"Grupo Creado Exitosamente", 
                message:'El grupo se ha creado de forma satisfactoria'
            });
        }
    });
});

router.put('/update_group', verify_token, (req, res, next) => {
    var query = "" +
    " UPDATE smsreseller_grupos" +
    " SET grp_nombre = ?" +
    " WHERE id = ?";
    var values = [
        req.body.grp_nombre,
        req.body.id
    ];
    con.query(query, values, function(err, results, fields) {
        if(err){
            next(err);
        }else{
            res.status(200).json({
                title:"Grupo Editado Exitosamente", 
                message:'El grupo se ha editado de forma satisfactoria'
            });
        }
    });
});

router.delete('/delete_group', verify_token, (req, res, next) => {
    var query = "" +
    " DELETE FROM" +
    " smsreseller_grupos" +
    " WHERE id = ? AND smsadmin_resellers_id = ?";
    var values = [
        req.query.id,
        req.smsadmin_resellers_id
    ];
    con.query(query, values, function(err, results, fields) {
        if(err) {
            next(err);
        }else{
            res.status(200).json({
                title:"Grupo Eliminado Exitosamente", 
                message:'El grupo se ha eliminado de forma satisfactoria'
            });
        }
    });
});*/

//GROUPS #################################################################
//########################################################################

//########################################################################
//CATALOGS ###############################################################

//CATALOGS ###############################################################
//########################################################################

//########################################################################
//UTILS ##################################################################

function generate_recovery_code(size) {
    var result = '';
    var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    for (var i = 0; i < size; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function encrypt(text) {
    var cipher = crypto.createCipher(algorithm, Buffer.from(key), iv)
    var crypted = cipher.update(text, 'utf8', 'hex')
    crypted += cipher.final('hex');
    return crypted;
}

function decrypt(text) {
    var decipher = crypto.createDecipher(algorithm, Buffer.from(key), iv)
    var dec = decipher.update(text, 'hex', 'utf8')
    dec += decipher.final('utf8');
    return dec;
}

//UTILS ##################################################################
//########################################################################

module.exports = router;