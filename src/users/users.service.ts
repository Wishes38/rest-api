import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { User } from './shemas/user.schema';
import * as crypto from 'crypto';
import * as nodemailer from 'nodemailer';
import * as dotenv from 'dotenv';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class UsersService {
    constructor(@InjectModel(User.name) private userModel: Model<User>) { }

    async createUser(registerDto: RegisterDto): Promise<User> {
        const hashedPassword = await bcrypt.hash(registerDto.password, 10);
        const newUser = new this.userModel({
            email: registerDto.email,
            password: hashedPassword,
            roles: registerDto.roles || ['user'],
            firstName: registerDto.firstName ?? '',
            lastName: registerDto.lastName ?? '',
            avatarUrl: registerDto.avatarUrl ?? '',
        });
        return newUser.save();
    }

    async findUserByEmail(email: string): Promise<User | null> {
        const user = await this.userModel.findOne({ email }).exec();
        return user || null;
    }


    async requestPasswordReset(email: string): Promise<void> {
        const user = await this.findUserByEmail(email);
        if (!user) {
            throw new BadRequestException('User not found');
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expires = new Date();
        expires.setHours(expires.getHours() + 1);

        user.resetPasswordToken = token;
        user.resetPasswordExpires = expires;
        await user.save();

        dotenv.config();

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD,
            },
        });

        const resetUrl = `http://localhost:3000/users/reset-password/${token}`;
        const mailOptions = {
            to: user.email,
            subject: 'Password Reset',
            text: `You requested a password reset. Please click this link to reset your password: ${resetUrl}`,
        };

        await transporter.sendMail(mailOptions);
    }

    async findUserByResetToken(token: string): Promise<User | null> {
        return this.userModel.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: new Date() },
        }).exec();
    }

    async resetPassword(token: string, newPassword: string): Promise<void> {
        const user = await this.findUserByResetToken(token);
        if (!user) {
            throw new BadRequestException('Invalid or expired token');
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetPasswordToken = null;
        user.resetPasswordExpires = null;

        await user.save();
    }

    async updateRefreshToken(userId: string, refreshToken: string): Promise<void> {
        await this.userModel.findByIdAndUpdate(userId, { refreshToken }).exec();
    }

    async findUserById(userId: string): Promise<User | null> {
        return this.userModel.findById(userId).exec();
    }


    async updateProfile(userId: string, updates: Partial<User>): Promise<User> {
        const user = await this.userModel.findById(userId);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        if (updates.password) {
            updates.password = await bcrypt.hash(updates.password, 10);
        }

        Object.assign(user, updates);
        return user.save();
    }

}
