import * as mongoose from 'mongoose'

export type InvalidToken = {
    _id: string
    token: string
}

const BlacklistEntrySchema = new mongoose.Schema(
    {
        token: { type: String, index: true },
        createdAt: { type: Date, expires: '1d', default: Date.now },
    },
    { timestamps: true }
)

export type InvalidTokenType = InvalidToken & mongoose.Document
export const BlacklistEntryModel = mongoose.model<InvalidTokenType>(
    'Blacklist',
    BlacklistEntrySchema
)
