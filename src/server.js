require('dotenv').config()
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const archiver = require('archiver');
const unzipper = require('unzipper');
const { pipeline } = require('stream/promises');
const os = require('os');

const app = express();
app.use(cors()); // Permite que seu frontend acesse os dados

const CAMINHO_RAIZ = process.env.ROOT_PATH
const PORTA = process.env.PORT
const PASTA_BASE_DESTINO = process.env.TARGET_PATH

// Helper para calcular SHA256 de um arquivo
function calcularHashStream(caminhoArquivo) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(caminhoArquivo);

        stream.on('error', reject);
        hash.on('error', reject);

        stream.on('end', () => {
            resolve(hash.digest('hex'));
        });

        stream.pipe(hash, { end: true });
    });
}


// Helper recursivo para buscar arquivos (profundidade 5)
function buscarArquivosParaZip(dir, profundidade = 0) {
    let resultados = [];
    if (profundidade > 5) return resultados;

    const itens = fs.readdirSync(dir, { withFileTypes: true });
    for (const item of itens) {
        const caminhoCompleto = path.join(dir, item.name);
        if (item.isDirectory()) {
            resultados = resultados.concat(buscarArquivosParaZip(caminhoCompleto, profundidade + 1));
        } else {
            if (item.name.startsWith('hashlog.') || item.name === 'Lista de Arquivos.csv') {
                resultados.push(caminhoCompleto);
            }
        }
    }
    return resultados;
}

app.get('/api/pastas', (req, res) => {
    try {
        // Pega o caminho enviado pelo frontend ou usa vazio para a raiz
        const subDiretorio = req.query.caminho || '';
        const caminhoCompleto = path.join(CAMINHO_RAIZ, subDiretorio);

        console.log(caminhoCompleto)

        // Segurança: Impede que o usuário tente sair da pasta base
        if (!caminhoCompleto.startsWith(CAMINHO_RAIZ)) {
            return res.status(403).json({ error: "Acesso negado" });
        }

        const itens = fs.readdirSync(caminhoCompleto, { withFileTypes: true });
        
        const conteudo = itens.map(item => ({
            nome: item.name,
            ehDiretorio: item.isDirectory(),
            // Guarda o caminho relativo para a próxima busca
            caminhoRelativo: path.join(subDiretorio, item.name)
        }));

        res.json(conteudo);
    } catch (error) {
        console.error("Erro ao ler pasta:", error);
        res.status(500).json({ error: "Nao foi possível acessar a pasta" });
    }
});

app.get('/api/get-hash', async (req, res) => {
    try {
        const { caminho } = req.query;
        const pastaAlvo = path.join(CAMINHO_RAIZ, caminho);

        // 1. Identificar pasta do processo
        const partesCaminho = pastaAlvo.split(path.sep);
        const regexPastaProcesso = /^\d{4}\.\d{7}.*/;

        let nomePastaProcesso = null;
        for (let i = partesCaminho.length - 1; i >= 0; i--) {
            if (regexPastaProcesso.test(partesCaminho[i])) {
                nomePastaProcesso = partesCaminho[i];
                break;
            }
        }

        if (!nomePastaProcesso) {
            throw new Error("Pasta do processo não identificada.");
        }

        // 2. Nome do ZIP esperado
        const nomeSubpastaAtual = path.basename(pastaAlvo) || 'raiz';
        const nomeZipEsperado = `anexo-laudo-${nomeSubpastaAtual}.zip`;

        if (!fs.existsSync(PASTA_BASE_DESTINO)) {
            throw new Error("Pasta base de destino não existe.");
        }

        // 3. Procurar o ZIP em todos os anos (ordem decrescente)
        const anos = fs.readdirSync(PASTA_BASE_DESTINO, { withFileTypes: true })
            .filter(d => d.isDirectory() && /^\d{4}$/.test(d.name))
            .map(d => d.name)
            .sort((a, b) => Number(b) - Number(a));

        let caminhoZipEncontrado = null;

        for (const ano of anos) {
            const caminhoProcesso = path.join(
                PASTA_BASE_DESTINO,
                ano,
                nomePastaProcesso
            );

            const caminhoZip = path.join(caminhoProcesso, nomeZipEsperado);
            if (fs.existsSync(caminhoZip)) {
                caminhoZipEncontrado = caminhoZip;
                break;
            }
        }

        if (!caminhoZipEncontrado) {
            return res.status(404).json({
                error: "Arquivo ZIP não encontrado."
            });
        }

        // 4. Ler hashes.txt do ZIP via STREAM
        const zipStream = fs.createReadStream(caminhoZipEncontrado)
            .pipe(unzipper.Parse({ forceStream: true }));

        for await (const entry of zipStream) {
            if (entry.path === 'root_hash.txt') {
                const hash = (await entry.buffer()).toString('utf8').trim();
                return res.json({ rootHash: hash });
            }

            if (entry.path === 'hashes.txt') {
                const hashStream = crypto.createHash('sha256');

                await pipeline(
                    entry,
                    hashStream
                );

                const rootHash = hashStream.digest('hex');
                return res.json({ rootHash });
            }

            entry.autodrain();
        }

        throw new Error("hashes.txt não encontrado dentro do ZIP.");

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.get('/api/has-zip', async (req, res) => {
    try {
        const { caminho } = req.query; // ex: '2020.1234567/auto1'
        if (!caminho) return res.json({ status: "invalid" });

        const pastaAlvo = path.join(CAMINHO_RAIZ, caminho);
        const partes = caminho.split(path.sep);

        // 1. Identifica a pasta do processo (ex: 2020.1234567)
        const regexProcesso = /^\d{4}\.\d{7}.*/;
        let nomePastaProcesso = null;
        for (let i = partes.length - 1; i >= 0; i--) {
        if (regexProcesso.test(partes[i])) {
            nomePastaProcesso = partes[i];
            break;
        }
        }
        if (!nomePastaProcesso) return res.json({ status: "invalid" });

        // 2. Define o ZIP esperado para esta subpasta
        const pastaAtual = partes[partes.length - 1];
        const nomeZipEsperado = `anexo-laudo-${pastaAtual}.zip`;

        // 3. Verifica se a pasta base de destino existe
        if (!fs.existsSync(PASTA_BASE_DESTINO)) return res.json({ status: "empty" });

        // 4. Percorre os anos
        const anos = fs.readdirSync(PASTA_BASE_DESTINO, { withFileTypes: true })
        .filter(d => d.isDirectory() && /^\d{4}$/.test(d.name))
        .map(d => d.name)
        .sort((a, b) => Number(b) - Number(a)); // do mais recente

        for (const ano of anos) {
        const caminhoProcesso = path.join(PASTA_BASE_DESTINO, ano, nomePastaProcesso);
        if (!fs.existsSync(caminhoProcesso)) continue;

        const arquivos = fs.readdirSync(caminhoProcesso);
        if (arquivos.includes(nomeZipEsperado)) {
            return res.json({ status: "hasZip", nomeZip: nomeZipEsperado, anoEncontrado: ano });
        }
        }

        // Se não encontrou nenhum ZIP correspondente
        return res.json({ status: "empty" });

    } catch (err) {
        console.error("Erro em has-zip:", err);
        return res.status(500).json({ status: "invalid", error: err.message });
    }
    });





app.post('/api/mkzip', express.json(), async (req, res) => {
    try {
        const { caminho } = req.body;
        const pastaAlvo = path.join(CAMINHO_RAIZ, caminho);

        // 1. Pega a pasta atual e a pasta pai imediata
        const pastaAtual = path.basename(pastaAlvo); 
        const pastaPai = path.basename(path.dirname(pastaAlvo)); // só a pasta pai

        const regexPastaProcesso = /^\d{4}\.\d{7}.*/;

        // 2. Verifica se a pasta pai tem o formato correto
        if (!regexPastaProcesso.test(pastaPai)) {
            throw new Error(
                "A pasta pai da pasta atual deve estar no formato 'aaaa.xxxxxxx'."
            );
        }

        const nomePastaProcesso = pastaPai; // usamos a pasta pai como referência do processo

        // 3. Define o destino usando o ANO ATUAL
        const anoAtual = new Date().getFullYear().toString(); // ex: "2026"
        const caminhoDestinoFinal = path.join(PASTA_BASE_DESTINO, anoAtual, nomePastaProcesso);

        // Cria a estrutura de pastas se não existir
        if (!fs.existsSync(caminhoDestinoFinal)) {
            fs.mkdirSync(caminhoDestinoFinal, { recursive: true });
        }

        // 4. Busca arquivos para o ZIP
        const arquivosEncontrados = buscarArquivosParaZip(pastaAlvo);
        if (arquivosEncontrados.length === 0) {
            throw new Error("Nenhum arquivo 'hashlog.*' ou 'Lista de Arquivos.csv' encontrado.");
        }

        // 5. Gera hashes e conteúdo do ZIP
        let hashesContent = "";
        for (const arq of arquivosEncontrados) {
            const hash = await calcularHashStream(arq);
            hashesContent += `${hash} ${arq}\n`;
        }
        const rootHash = crypto.createHash('sha256').update(hashesContent).digest('hex');

        // 6. Define nome do ZIP
        const nomeArquivoZip = `anexo-laudo-${pastaAtual}.zip`;
        const caminhoCompletoZip = path.join(caminhoDestinoFinal, nomeArquivoZip);

        const output = fs.createWriteStream(caminhoCompletoZip);
        const archive = archiver('zip', { zlib: { level: 9 } });

        output.on('close', () => {
            res.json({
                success: true,
                local: caminhoCompletoZip,
                rootHash,
                processo: nomePastaProcesso
            });
        });

        archive.on('error', err => { throw err; });
        archive.pipe(output);

        arquivosEncontrados.forEach(arq => {
            const nomeRelativo = path.relative(pastaAlvo, arq);
            archive.file(arq, { name: nomeRelativo });
        });

        archive.append(hashesContent, { name: 'hashes.txt' });
        // archive.append(rootHash, { name: 'root_hash.txt' }); // opcional

        await archive.finalize();

    } catch (error) {
        console.error("Erro MKZIP:", error);
        res.status(500).json({ error: error.message });
    }
});


app.listen(PORTA, '0.0.0.0', () => {
    console.log("Servidor rodando em http://localhost:3001");
    console.log("Acesse http://localhost:3001/api/pastas para ver os dados");
    console.log(`Caminho raíz: ${CAMINHO_RAIZ}`)
    console.log(`Porta: ${PORTA}`)
});