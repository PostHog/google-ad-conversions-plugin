import jwt from 'jsonwebtoken'
import fetch from 'node-fetch'

export async function exportEvents(events, meta) {
    // await Promise.all(events.filter(e => e.properties.gclid).map(e => uploadConversion(e.properties.gclid, meta)))
}


export async function setupPlugin(meta) {
    await setGlobals(meta)

    await uploadConversion("random-gclid", meta)
}

export async function setGlobals(meta) {
    const { global, attachments, config } = meta
    global.privateKey = JSON.parse(attachments?.privateKey?.contents)
    if (!global.privateKey || !global.privateKey['private_key']) {
        throw new Error('Private Key not found in JSON')
    }
    global.accessToken = await getAccessToken(meta)
    global.developerToken = config.developerToken
    global.customerId = config.customerId.split(/[^0-9]/g).join('')
    global.managerId = config.managerId.split(/[^0-9]/g).join('')
}

async function getAccessToken ({ global, cache }) {
    const accessToken = await cache.get('access_token')
    if (accessToken) {
        return accessToken
    }

    const authResponse = await fetchAccessToken(global.privateKey)
    await cache.set('access_token', authResponse['access_token'], Math.floor(authResponse['expires_in'] * 0.9))

    return authResponse['access_token']
}

async function fetchAccessToken(privateKey) {
    const time = Math.floor(new Date().valueOf() / 1000)
    const payload = {
        "iss": privateKey['client_email'],
        "scope": 'https://www.googleapis.com/auth/adwords',
        "aud": 'https://oauth2.googleapis.com/token',
        "exp": time + 3600,
        "iat": time
    }
    const token = jwt.sign(payload, privateKey['private_key'], { algorithm: 'RS256'});
    const requestPayload = {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: token
    }

    const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body: Object.entries(requestPayload).map(
            ([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`
        ).join('&')
    })
    const authResponse = await response.json()

    if (!authResponse['access_token']) {
        throw new Error('Can not get access token from /token auth response')
    }

    return authResponse
}

async function uploadConversion (gclid, meta) {
    const url = `https://googleads.googleapis.com/v8/customers/${meta.global.customerId}/googleAds:searchStream`
    const options = {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${meta.global.accessToken}`,
            'login-customer-id': meta.global.managerId,
            'developer-token': meta.global.developerToken,
            'content-type': 'application/json'
        },
        body: JSON.stringify({
            "query": `
            SELECT campaign.name,
                campaign_budget.amount_micros,
                campaign.status,
                campaign.optimization_score,
                campaign.advertising_channel_type,
                metrics.clicks,
                metrics.impressions,
                metrics.ctr,
                metrics.average_cpc,
                metrics.cost_micros,
                campaign.bidding_strategy_type
            FROM campaign
            WHERE segments.date DURING LAST_7_DAYS
                AND campaign.status != 'REMOVED'
            `
        })
    }
    console.log({ url, options })

    const response = await fetch(url, options)
    console.log(await response.text())

}