import * as mongoose from "mongoose";
import * as bcrypt from 'bcrypt';

export interface User {
    _id: string;
    name: string;
    email: string;
    password?: string;
    passwordHash: string;
    avatarUrl: string;
    resetToken?: string;
    resetPasswordExpires?: number;
}

const UserSchema = new mongoose.Schema({
    name: {type: String, required: true},
    email: {type: String, required: true, unique: true, index: true},
    passwordHash: {type: String, required: true},
    avatarUrl: {type: String},
    resetToken: {type: String},
    resetPasswordExpires: {type: Number}
}, {timestamps: true});
UserSchema.methods.validPassword = function (password): Promise<boolean> {
    return bcrypt.compare(password, this.passwordHash.toString());
};
UserSchema.virtual("password").set(function (value) {
    this.passwordHash = bcrypt.hashSync(value, 12);
});
export type UserType = User & mongoose.Document & {
    validPassword(password: string): Promise<boolean>
};
export const UserModel = mongoose.model<UserType>('User', UserSchema);