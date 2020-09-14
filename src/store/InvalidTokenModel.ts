import * as mongoose from "mongoose";

export type InvalidToken = {
    _id: string;
    token: string;
};

const InvalidTokenSchema = new mongoose.Schema({
    token: {type: String, index: true},
    createdAt: { type: Date, expires: '24h', default: Date.now }
}, {timestamps: true});

export type InvalidTokenType = InvalidToken & mongoose.Document;
export const InvalidTokenModel = mongoose.model<InvalidTokenType>('Blacklist', InvalidTokenSchema);