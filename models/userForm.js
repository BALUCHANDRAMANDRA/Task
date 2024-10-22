const mongoose = require('mongoose');
const Schema = new mongoose.Schema({
    username:{
        type: String,
        required: true
    },
    socialMedia:{
        type: String,
        required: true
    },
    images:{
        type: [String],
        required: true
    }
},{ timestamps: true })

const userForm = mongoose.model('UserForm', Schema);
module.exports = userForm;