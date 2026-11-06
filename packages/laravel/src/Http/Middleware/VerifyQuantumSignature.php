<?php

declare(strict_types=1);

namespace Zubaer\LaravelZubQuant\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Zubaer\ZubQuant\ZubQuant;

/**
 * Verifies incoming requests/webhooks signed with ML-DSA-65 (NIST FIPS 204).
 */
class VerifyQuantumSignature
{
    public function handle(Request $request, Closure $next, ?string $verifyKeyConfig = null): Response
    {
        $token = $request->header('X-ZubQuant-Signature');
        $verifyKey = $verifyKeyConfig ?? (function_exists('config') ? config('zubquant.verify_key') : null);

        if (empty($token) || empty($verifyKey)) {
            abort(401, 'Missing Post-Quantum Signature (X-ZubQuant-Signature).');
        }

        $result = ZubQuant::verify((string) $token, (string) $verifyKey);
        if (!$result['valid'] || !hash_equals((string) $result['payload'], $request->getContent())) {
            abort(403, 'Invalid ML-DSA-65 Post-Quantum Signature.');
        }

        return $next($request);
    }
}

