import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class User extends Document {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ type: [String], default: ['user'] })
  roles: string[];

  @Prop({ required: false })
  firstName?: string;

  @Prop({ required: false })
  lastName?: string;

  @Prop({ required: false })
  avatarUrl?: string;

  @Prop({ default: null })
  resetPasswordToken: string | null;

  @Prop({ default: null })
  resetPasswordExpires: Date | null;

  @Prop({ default: null })
  refreshToken: string | null;

  @Prop({ default: null })
  googleId?: string | null;
}

export const UserSchema = SchemaFactory.createForClass(User);

