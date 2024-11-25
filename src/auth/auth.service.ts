import { forwardRef, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { InjectModel } from '@nestjs/mongoose';
import { BlacklistedToken } from './schemas/blacklist.schema';
import { Model } from 'mongoose';

@Injectable()
export class AuthService {
  constructor(
    @Inject(forwardRef(() => UsersService))
    private usersService: UsersService,
    private readonly jwtService: JwtService,
    @InjectModel(BlacklistedToken.name) private blacklistedTokenModel: Model<BlacklistedToken>
  ) { }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findUserByEmail(email);
    if (user && (await bcrypt.compare(password, user.password))) {
      const { password, ...result } = user.toObject();
      return result;
    }
    throw new UnauthorizedException('Invalid credentials');
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user._id, roles: user.roles };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async logout(token: string): Promise<{ message: string }> {
    const isBlacklisted = await this.isTokenBlacklisted(token);

    if (isBlacklisted) {
      return { message: 'Token is already blacklisted' };
    }

    const blacklistedToken = new this.blacklistedTokenModel({ token });
    await blacklistedToken.save();

    return { message: 'Logout successful' };
  }


  async isTokenBlacklisted(token: string): Promise<boolean> {
    const tokenExists = await this.blacklistedTokenModel.findOne({ token }).exec();
    return !!tokenExists;
  }

}
