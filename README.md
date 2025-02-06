# 🎧 P2P Sesli & Yazılı Sohbet Uygulaması

Bu proje, uçtan uca şifrelenmiş, sesli ve yazılı bir **Peer-to-Peer (P2P) sohbet** uygulamasıdır. **Gürültü engelleme**, **şifreleme**, **dosya & resim paylaşımı** gibi gelişmiş özellikler içerir.

![Anime Girl](https://media.tenor.com/SOMETHING_RANDOM.gif)

## 🚀 Özellikler
- 🔊 **Gerçek zamanlı ses iletimi** (UDP protokolü ile doğrudan bağlantı)
- 🔐 **AES-256 ile uçtan uca şifreleme**
- 🎤 **Gürültü engelleme** ve **ses seviyesi ayarı**
- 📁 **Dosya & resim gönderme**
- 🖥️ **Modern ve kullanıcı dostu GUI** (Tkinter ile)
- 👥 **P2P bağlantı: Merkezi sunucu gerektirmez!**

![P2P Network](https://media.tenor.com/SOME_NETWORK_GIF.gif)

## 📦 Kurulum

Öncelikle gerekli bağımlılıkları yükleyin:
```bash
pip install -r requirements.txt
```
Uygulamayı başlatın:
```bash
python bsdd.py
```

## 🎮 Kullanım
1. Uygulamayı çalıştırın 🚀
2. Sohbet portunu belirleyin (Öntanımlı: 5000)
3. Bağlanmak istediğiniz **IP** ve **portu** girin
4. **Sesli & yazılı sohbetin tadını çıkarın!** 🎉

## 📷 Ekran Görüntüleri

🌟 **Ana Arayüz**:
![UI](https://media.tenor.com/SOME_UI_GIF.gif)

🔊 **Gerçek zamanlı sesli iletişim**:
![Voice Chat](https://media.tenor.com/SOME_VOICE_CHAT_GIF.gif)

## 📜 Teknik Detaylar
- **Python (socket, threading, tkinter)** kullanılarak geliştirildi
- **AES-256 şifreleme** ile mesaj güvenliği sağlandı
- **Gürültü engelleme (NoiseReduce)** desteği ile temiz ses aktarımı
- **UDP NAT Traversal & Hole Punching** ile doğrudan bağlantı

## 📝 Lisans
MIT Lisansı altında sunulmaktadır.

---
**💖 Eğer beğendiyseniz, ⭐ bırakmayı unutmayın!**
