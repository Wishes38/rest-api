import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class BlacklistedToken extends Document {
  @Prop({ required: true, unique: true })
  token: string;
}

export const BlacklistedTokenSchema = SchemaFactory.createForClass(BlacklistedToken);
