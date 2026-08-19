const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const createHttpError = require('http-errors');
const ApiKey = require('../../models/root/ApiKey');
const Tenant = require('../../models/root/Tenant');
const TenantUserMap = require('../../models/root/TenantUserMap');
const getTenantModel = require('../../utils/getTenantModel');
const userSchema = require('../../models/tenant/userSchema');
const roleSchema = require('../../models/tenant/roleSchema');
const tokenGenrator = require('../../utils/tokenGenrator');
const { STATUS_CODE, ERROR_MESSAGE } = require('../../utils/constant');

module.exports = async function (ssoData) {
    const { apiKey, ssoToken } = ssoData;
    if (!apiKey || !ssoToken) {
        throw new createHttpError(STATUS_CODE.BAD_REQUEST, 'apiKey and ssoToken are required');
    }

    const hashedApiKey = crypto.createHash('sha256').update(apiKey).digest('hex');
    const apiKeyDoc = await ApiKey.findOne({ key_hash: hashedApiKey, isActive: true })
        .select('+sso_secret')
        .populate('tenantId');

    if (!apiKeyDoc || !apiKeyDoc.tenantId) {
        throw new createHttpError(STATUS_CODE.UNAUTHORIZED, 'Invalid or inactive API Key');
    }

    let decoded;
    try {
        decoded = jwt.verify(ssoToken, apiKeyDoc.sso_secret);
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            throw new createHttpError(STATUS_CODE.UNAUTHORIZED, 'SSO Token has expired');
        }
        throw new createHttpError(STATUS_CODE.UNAUTHORIZED, 'Invalid SSO Token signature');
    }

    if (!decoded.email) {
        throw new createHttpError(STATUS_CODE.BAD_REQUEST, 'SSO token payload must contain an email address');
    }

    const tenant = apiKeyDoc.tenantId;
    const email = decoded.email.toLowerCase().trim();

    const User = getTenantModel(tenant.dbName, 'User', userSchema);
    const Role = getTenantModel(tenant.dbName, 'Role', roleSchema);

    let user = await User.findOne({ email }).populate('role', 'name');

    if (!user) {
        let role = null;
        if (decoded.role) {
            role = await Role.findOne({ name: new RegExp(`^${decoded.role}$`, 'i') });
        }
        if (!role) {
            role = await Role.findOne({ name: 'Member' }) || await Role.findOne({});
        }

        const fullName = decoded.name || '';
        const firstName = decoded.firstName || fullName.split(' ')[0] || 'SSO';
        const lastName = decoded.lastName || fullName.split(' ').slice(1).join(' ') || 'User';

        user = await User.create({
            firstName,
            lastName,
            email,
            password: crypto.randomBytes(20).toString('hex'),
            role: role?._id,
            status: 'active'
        });

        user = await User.findById(user._id).populate('role', 'name');
    }

    let map = await TenantUserMap.findOne({ email, tenantId: tenant._id });
    if (!map) {
        map = await TenantUserMap.create({
            email,
            tenantId: tenant._id,
            status: 'active'
        });
    }

    const mapping = {
        tenantId: {
            _id: tenant._id,
            slug: tenant.slug
        }
    };

    const { accessToken, refreshToken } = await tokenGenrator(User, user._id, mapping);

    // Update last used timestamp for apiKey
    apiKeyDoc.lastUsedAt = new Date();
    await apiKeyDoc.save();

    user.lastLogin = Date.now();
    user.lastActivateAt = Date.now();
    await user.save({ validateBeforeSave: false });

    return {
        user: {
            _id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.role
        },
        slug: tenant.slug,
        accessToken,
        refreshToken
    };
};
