'use strict';

const async = require('async');
const moment = require('moment');
const useragent = require('useragent');
const express = require('express');
const Webtask = require('webtask-tools');
const app = express();
const Mixpanel = require('mixpanel');
const Request = require('request');
const memoizer = require('lru-memoizer');

function lastLogCheckpoint(req, res) {
  let ctx = req.webtaskContext;
  let required_settings = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET', 'MIXPANEL_TOKEN', 'MIXPANEL_KEY'];
  let missing_settings = required_settings.filter((setting) => !ctx.data[setting]);

  if (missing_settings.length) {
    return res.status(400).send({message: 'Missing settings: ' + missing_settings.join(', ')});
  }

  // If this is a scheduled task, we'll get the last log checkpoint from the previous run and continue from there.
  req.webtaskContext.storage.get((err, data) => {
    let startCheckpointId = typeof data === 'undefined' ? null : data.checkpointId;

    if (err) {
      console.log('storage.get', err);
    }

    // Create a new event logger
    const Logger = Mixpanel.init(ctx.data.MIXPANEL_TOKEN, {
      key: ctx.data.MIXPANEL_KEY
    });

    Logger.error = function (err, context) {
      // Handle errors here
      console.log("error", err, "context", context);
    };

    // Start the process.
    async.waterfall([
      (callback) => {
        const getLogs = (context) => {
          console.log(`Logs from: ${context.checkpointId || 'Start'}.`);

          let take = Number.parseInt(ctx.data.BATCH_SIZE);

          take = take > 100 ? 100 : take;

          context.logs = context.logs || [];

          getLogsFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, take, context.checkpointId, (logs, err) => {
            if (err) {
              console.log('Error getting logs from Auth0', err);
              return callback(err);
            }

            if (logs && logs.length) {
              logs.forEach((l) => context.logs.push(l));
              context.checkpointId = context.logs[context.logs.length - 1]._id;
              // return setImmediate(() => getLogs(context));
            }

            console.log(`Total logs: ${context.logs.length}.`);
            return callback(null, context);
          });
        };

        getLogs({checkpointId: startCheckpointId});
      },
      (context, callback) => {
        const min_log_level = parseInt(ctx.data.LOG_LEVEL) || 0;
        const log_matches_level = (log) => {
          if (logTypes[log.type]) {
            return logTypes[log.type].level >= min_log_level;
          }
          return true;
        };

        const types_filter = (ctx.data.LOG_TYPES && ctx.data.LOG_TYPES.split(',')) || [];
        const log_matches_types = (log) => {
          if (!types_filter || !types_filter.length) return true;
          return log.type && types_filter.indexOf(log.type) >= 0;
        };

        context.logs = context.logs
          .filter(l => l.type !== 'sapi' && l.type !== 'fapi')
          .filter(log_matches_level)
          .filter(log_matches_types);

        callback(null, context);
      },
      (context, callback) => {
        console.log(`Sending ${context.logs.length}`);
        if (context.logs.length > 0) {
          const now = Date.now();
          const mixpanelEvents = context.logs.map(function (log) {
            const eventName = logTypes[log.type].name;
            // TODO - consider setting the time to date in the underlying log file?
            // log.time = log.date;
            log.time = now;
            log.distinct_id = 'auth0-logs';
            return {
              event: eventName,
              properties: log
            };
          });

          // import all events at once
          Logger.import_batch(mixpanelEvents, function(errorList) {
            if (errorList && errorList.length > 0) {
              console.log('Errors occurred sending logs to Mixpanel:', JSON.stringify(errorList));
              return callback(errorList);
            }
            console.log('Upload complete.');
            return callback(null, context);
          });
        } else {
          // no logs, just callback
          console.log('No logs to upload - completed.');
          return callback(null, context);
        }
      }
    ], function (err, context) {
      if (err) {
        console.log('Job failed.', err);

        return req.webtaskContext.storage.set({checkpointId: startCheckpointId}, {force: 1}, (error) => {
          if (error) {
            console.log('Error storing startCheckpoint', error);
            return res.status(500).send({error: error});
          }

          res.status(500).send({
            error: err
          });
        });
      }

      console.log('Job complete.');

      return req.webtaskContext.storage.set({
        checkpointId: context.checkpointId,
        totalLogsProcessed: context.logs.length
      }, {force: 1}, (error) => {
        if (error) {
          console.log('Error storing checkpoint', error);
          return res.status(500).send({error: error});
        }

        res.sendStatus(200);
      });
    });

  });
}

const logTypes = {
  s: {
    name: 'Success Login',
    icon: 'icon-budicon-448',
    level: 1 // Info
  },
  ssa: {
    name: 'Success Silent Auth',
    icon: 'icon-budicon-448',
    level: 1 // Info
  },
  fsa: {
    name: 'Failed Silent Auth',
    icon: 'icon-budicon-448',
    level: 3 // Error
  },
  seacft: {
    name: 'Success Exchange',
    description: 'Authorization Code for Access Token',
    icon: 'icon-budicon-456',
    level: 1 // Info
  },
  feacft: {
    name: 'Failed Exchange',
    description: 'Authorization Code for Access Token',
    icon: 'icon-budicon-456',
    level: 3 // Error
  },
  seccft: {
    name: 'Success Exchange',
    description: 'Client Credentials for Access Token',
    icon: 'icon-budicon-456',
    level: 1 // Info
  },
  feccft: {
    name: 'Failed Exchange',
    description: 'Client Credentials for Access Token',
    icon: 'icon-budicon-456',
    level: 3 // Error
  },
  sepft: {
    name: 'Success Exchange',
    description: 'Password for Access Token',
    icon: 'icon-budicon-456',
    level: 1 // Info
  },
  fepft: {
    name: 'Failed Exchange',
    description: 'Password for Access Token',
    icon: 'icon-budicon-456',
    level: 3 // Error
  },
  sertft: {
    name: 'Success Exchange',
    description: 'Refresh Token for Access Token',
    icon: 'icon-budicon-456',
    level: 1 // Info
  },
  fertft: {
    name: 'Failed Exchange',
    description: 'Refresh Token for Access Token',
    icon: 'icon-budicon-456',
    level: 3 // Error
  },
  seoobft: {
    name: 'Success Exchange',
    description: 'Password and OOB Challenge for Access Token',
    icon: 'icon-budicon-456',
    level: 1 // Info
  },
  feoobft: {
    name: 'Failed Exchange',
    description: 'Password and OOB Challenge for Access Token',
    icon: 'icon-budicon-456',
    level: 3 // Error
  },
  seotpft: {
    name: 'Success Exchange',
    description: 'Password and OTP Challenge for Access Token',
    icon: 'icon-budicon-456',
    level: 1 // Info
  },
  feotpft: {
    name: 'Failed Exchange',
    description: 'Password and OTP Challenge for Access Token',
    icon: 'icon-budicon-456',
    level: 3 // Error
  },
  sercft: {
    name: 'Success Exchange',
    description: 'Password and MFA Recovery code for Access Token',
    icon: 'icon-budicon-456',
    level: 1 // Info
  },
  fercft: {
    name: 'Failed Exchange',
    description: 'Password and MFA Recovery code for Access Token',
    icon: 'icon-budicon-456',
    level: 3 // Error
  },
  f: {
    name: 'Failed Login',
    icon: 'icon-budicon-448',
    level: 3 // Error
  },
  w: {
    name: 'Warning',
    icon: 'icon-budicon-354',
    level: 2 // Warning
  },
  du: {
    name: 'Deleted User',
    icon: 'icon-budicon-311',
    level: 3 // Error
  },
  fu: {
    name: 'Failed Login (invalid email/username)',
    icon: 'icon-budicon-311',
    level: 3 // Error
  },
  fp: {
    name: 'Failed Login (wrong password)',
    icon: 'icon-budicon-311',
    level: 3 // Error
  },
  fc: {
    name: 'Failed by Connector',
    icon: 'icon-budicon-313',
    level: 3 // Error
  },
  fco: {
    name: 'Failed by CORS',
    icon: 'icon-budicon-313',
    level: 3 // Error
  },
  con: {
    name: 'Connector Online',
    icon: 'icon-budicon-143',
    level: 1 // Info
  },
  coff: {
    name: 'Connector Offline',
    icon: 'icon-budicon-143',
    level: 3 // Error
  },
  fcpro: {
    name: 'Failed Connector Provisioning',
    icon: 'icon-budicon-143',
    level: 4 // Error
  },
  ss: {
    name: 'Success Signup',
    icon: 'icon-budicon-314',
    level: 1 // Info
  },
  fs: {
    name: 'Failed Signup',
    icon: 'icon-budicon-311',
    level: 3 // Error
  },
  cs: {
    name: 'Code Sent',
    icon: 'icon-budicon-243',
    level: 1 // Info
  },
  cls: {
    name: 'Code/Link Sent',
    icon: 'icon-budicon-781',
    level: 1 // Info
  },
  sv: {
    name: 'Success Verification Email',
    icon: 'icon-budicon-781',
    level: 1 // Info
  },
  fv: {
    name: 'Failed Verification Email',
    icon: 'icon-budicon-311',
    level: 3 // Error
  },
  scp: {
    name: 'Success Change Password',
    icon: 'icon-budicon-280',
    level: 1 // Info
  },
  fcp: {
    name: 'Failed Change Password',
    icon: 'icon-budicon-266',
    level: 3 // Error
  },
  sce: {
    name: 'Success Change Email',
    icon: 'icon-budicon-266',
    level: 1 // Info
  },
  fce: {
    name: 'Failed Change Email',
    icon: 'icon-budicon-266',
    level: 3 // Error
  },
  scu: {
    name: 'Success Change Username',
    icon: 'icon-budicon-266',
    level: 1 // Info
  },
  fcu: {
    name: 'Failed Change Username',
    icon: 'icon-budicon-266',
    level: 3 // Error
  },
  scpn: {
    name: 'Success Change Phone Number',
    icon: 'icon-budicon-266',
    level: 1 // Info
  },
  fcpn: {
    name: 'Failed Change Phone Number',
    icon: 'icon-budicon-266',
    level: 3 // Error
  },
  svr: {
    name: 'Success Verification Email Request',
    icon: 'icon-budicon-781',
    level: 0 // Info
  },
  fvr: {
    name: 'Failed Verification Email Request',
    icon: 'icon-budicon-311',
    level: 3 // Error
  },
  scpr: {
    name: 'Success Change Password Request',
    icon: 'icon-budicon-280',
    level: 1 // Info
  },
  fcpr: {
    name: 'Failed Change Password Request',
    icon: 'icon-budicon-311',
    level: 3 // Error
  },
  fn: {
    name: 'Failed Sending Notification',
    icon: 'icon-budicon-782',
    level: 3 // Error
  },
  sapi: {
    name: 'API Operation',
    icon: 'icon-budicon-546',
    level: 1 // Info
  },
  fapi: {
    name: 'Failed API Operation',
    icon: 'icon-budicon-546',
    level: 3 // Error
  },
  limit_wc: {
    name: 'Blocked Account',
    icon: 'icon-budicon-313',
    level: 4 // Error
  },
  limit_mu: {
    name: 'Blocked IP Address',
    icon: 'icon-budicon-313',
    level: 4 // Error
  },
  limit_ui: {
    name: 'Too Many Calls to /userinfo',
    icon: 'icon-budicon-313',
    level: 4 // Error
  },
  api_limit: {
    name: 'Rate Limit On API',
    icon: 'icon-budicon-313',
    level: 4 // Error
  },
  limit_delegation: {
    name: 'Too Many Calls to /delegation',
    icon: 'icon-budicon-313',
    level: 4 // Error
  },
  sdu: {
    name: 'Successful User Deletion',
    icon: 'icon-budicon-312',
    level: 1 // Info
  },
  fdu: {
    name: 'Failed User Deletion',
    icon: 'icon-budicon-311',
    level: 3 // Error
  },
  slo: {
    name: 'Success Logout',
    icon: 'icon-budicon-449',
    level: 1 // Info
  },
  flo: {
    name: 'Failed Logout',
    icon: 'icon-budicon-449',
    level: 3 // Error
  },
  sd: {
    name: 'Success Delegation',
    icon: 'icon-budicon-456',
    level: 1 // Info
  },
  fd: {
    name: 'Failed Delegation',
    icon: 'icon-budicon-456',
    level: 3 // Error
  },
  gd_unenroll: {
    name: 'Unenroll device account',
    icon: 'icon-budicon-298',
    level: 1 // Info
  },
  gd_update_device_account: {
    name: 'Update device account',
    icon: 'icon-budicon-257',
    level: 1 // Info
  },
  gd_module_switch: {
    name: 'Module switch',
    icon: 'icon-budicon-329',
    level: 1 // Info
  },
  gd_tenant_update: {
    name: 'Guardian tenant update',
    icon: 'icon-budicon-170',
    level: 1 // Info
  },
  gd_start_auth: {
    name: 'Second factor started',
    icon: 'icon-budicon-285',
    level: 1 // Info
  },
  gd_start_enroll: {
    name: 'Enroll started',
    icon: 'icon-budicon-299',
    level: 1 // Info
  },
  gd_user_delete: {
    name: 'User delete',
    icon: 'icon-budicon-298',
    level: 1 // Info
  },
  gd_auth_succeed: {
    name: 'OTP Auth suceed',
    icon: 'icon-budicon-mfa-login-succeed',
    level: 1 // Info
  },
  gd_auth_failed: {
    name: 'OTP Auth failed',
    icon: 'icon-budicon-mfa-login-failed',
    level: 3 // Error
  },
  gd_send_pn: {
    name: 'Push notification sent',
    icon: 'icon-budicon-mfa-send-pn',
    level: 1 // Info
  },
  gd_auth_rejected: {
    name: 'OTP Auth rejected',
    icon: 'icon-budicon-mfa-login-failed',
    level: 3 // Error
  },
  gd_recovery_succeed: {
    name: 'Recovery succeed',
    icon: 'icon-budicon-mfa-recovery-succeed',
    level: 1 // Info
  },
  gd_recovery_failed: {
    name: 'Recovery failed',
    icon: 'icon-budicon-mfa-recovery-failed',
    level: 3 // Error
  },
  gd_send_sms: {
    name: 'SMS Sent',
    icon: 'icon-budicon-799',
    level: 1 // Info
  },
  gd_otp_rate_limit_exceed: {
    name: 'Too many failures',
    icon: 'icon-budicon-435',
    level: 2 // Warning
  },
  gd_recovery_rate_limit_exceed: {
    name: 'Too many failures',
    icon: 'icon-budicon-435',
    level: 2 // Warning
  },
  fui: {
    name: 'Users import',
    icon: 'icon-budicon-299',
    level: 2 // Warning
  },
  sui: {
    name: 'Users import',
    icon: 'icon-budicon-299',
    level: 1 // Info
  },
  pwd_leak: {
    name: 'Breached password',
    icon: 'icon-budicon-313',
    level: 3 // Error
  }
};

module.exports = logTypes;
module.exports.get = function(type) {
  return (logTypes[type] && logTypes[type].name) || 'Unknown Log Type: ' + type;
};

function getLogsFromAuth0 (domain, token, take, from, cb) {
  var url = `https://${domain}/api/v2/logs`;

  Request({
    method: 'GET',
    url: url,
    json: true,
    qs: {
      take: take,
      from: from,
      sort: 'date:1',
      per_page: take
    },
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    }
  }, (err, res, body) => {
    if (err || res.statusCode !== 200) {
      console.log('Error getting logs', err);
      cb(null, err || body);
    } else {
      cb(body);
    }
  });
}

const getTokenCached = memoizer({
  load: (apiUrl, audience, clientId, clientSecret, cb) => {
    Request({
      method: 'POST',
      url: apiUrl,
      json: true,
      body: {
        audience: audience,
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret
      }
    }, (err, res, body) => {
      if (err) {
        cb(null, err);
      } else {
        cb(body.access_token);
      }
    });
  },
  hash: (apiUrl) => apiUrl,
  max: 100,
  maxAge: 1000 * 60 * 60
});

app.use(function (req, res, next) {
  var apiUrl = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/oauth/token`;
  var audience = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/api/v2/`;
  var clientId = req.webtaskContext.data.AUTH0_CLIENT_ID;
  var clientSecret = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

  getTokenCached(apiUrl, audience, clientId, clientSecret, function (access_token, err) {
    if (err) {
      console.log('Error getting access_token', err);
      return next(err);
    }

    req.access_token = access_token;
    next();
  });
});

app.get('/', lastLogCheckpoint);
app.post('/', lastLogCheckpoint);

module.exports = Webtask.fromExpress(app);




